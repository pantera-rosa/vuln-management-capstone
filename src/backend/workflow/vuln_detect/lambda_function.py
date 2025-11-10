import os
import sys
import shutil
import subprocess
import boto3

# Add the Lambda task root to Python path
sys.path.insert(0, os.environ.get('LAMBDA_TASK_ROOT', '/var/task'))

# Now import after path is set
from src.backend.workflow.vuln_detect.vuln_scan import extract_sbom, perform_vuln_scan

s3_client = boto3.client('s3')
sns_client = boto3.client('sns')

def lambda_handler(event, context):
    """
    Lambda handler for vulnerability scanning.
    Clones a repo, generates SBOM, scans for vulnerabilities, and uploads results to S3.
    """
    print("Starting vulnerability scan...")
    
    # Configuration
    repo_url = event.get('repo_url', "https://github.com/veracode/verademo.git")
    repo_dir = "/tmp/verademo"
    
    # Clean old clone if exists
    if os.path.exists(repo_dir):
        print(f"Cleaning old repository at {repo_dir}")
        shutil.rmtree(repo_dir)
    
    # Clone repository
    print(f"Cloning repository from {repo_url}...")
    try:
        subprocess.run(
            ["git", "clone", repo_url, repo_dir],
            check=True,
            capture_output=True,
            text=True
        )
        print(f"Repository cloned successfully to {repo_dir}")
    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e.stderr}")
        raise
    
    # Set up file paths
    sbom_path = "/tmp/verademo_sbom.spdx.json"
    scan_json_path = "/tmp/vuln_report.json"
    scan_parquet_path = "/tmp/vuln_report.parquet"
    
    # Extract SBOM
    print(f"Extracting SBOM to {sbom_path}...")
    extract_sbom(repo_dir, sbom_path)
    print("SBOM extraction complete")
    
    # Perform vulnerability scan
    print(f"Performing vulnerability scan...")
    vuln_df = perform_vuln_scan(
        sbom_path=sbom_path,
        output_scan_path=scan_json_path,
        output_pd_path=scan_parquet_path
    )
    print(f"Vulnerability scan complete. Found {len(vuln_df)} vulnerabilities")
    
    # Upload results to S3
    results_bucket = os.environ['S3_BUCKET']
    s3_prefix = f"verademo/scans/{context.aws_request_id}"
    
    print(f"Uploading results to s3://{results_bucket}/{s3_prefix}/")
    s3_client.upload_file(sbom_path, results_bucket, f"{s3_prefix}/sbom.spdx.json")
    s3_client.upload_file(scan_json_path, results_bucket, f"{s3_prefix}/vuln_report.json")
    s3_client.upload_file(scan_parquet_path, results_bucket, f"{s3_prefix}/vuln_report.parquet")
    print("Upload complete")
    
    # Optional: Send SNS notification
    if 'SNS_TOPIC_ARN' in os.environ:
        print("Sending SNS notification...")
        sns_topic = os.environ['SNS_TOPIC_ARN']
        msg = create_summary_message(vuln_df, s3_prefix, results_bucket)
        sns_client.publish(
            TopicArn=sns_topic,
            Subject="Vulnerability Scan Complete",
            Message=msg
        )
        print("SNS notification sent")
    
    # Return success response
    return {
        "statusCode": 200,
        "body": {
            "status": "completed",
            "s3_output": f"s3://{results_bucket}/{s3_prefix}/",
            "total_vulnerabilities": len(vuln_df),
            "request_id": context.aws_request_id
        }
    }

def create_summary_message(vuln_df, prefix, bucket):
    """Create a summary message for SNS notification."""
    total = len(vuln_df)
    summary = f"Vulnerability Scan Complete\n"
    summary += f"=" * 50 + "\n"
    summary += f"Total vulnerabilities found: {total}\n\n"
    
    if total > 0:
        # Count by severity
        if 'severity' in vuln_df.columns:
            severity_counts = vuln_df['severity'].value_counts().to_dict()
            summary += "Severity Breakdown:\n"
            for severity, count in sorted(severity_counts.items()):
                summary += f"  {severity}: {count}\n"
            summary += "\n"
    
    summary += f"Results Location:\n"
    summary += f"  s3://{bucket}/{prefix}/\n"
    summary += f"\nFiles:\n"
    summary += f"  - sbom.spdx.json\n"
    summary += f"  - vuln_report.json\n"
    summary += f"  - vuln_report.parquet\n"
    
    return summary