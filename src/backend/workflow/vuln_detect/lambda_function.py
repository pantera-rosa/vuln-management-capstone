import os
import json
import boto3
import subprocess
from datetime import datetime
from src.backend.workflow.vuln_detect.vuln_scan import extract_sbom, perform_vuln_scan

# Initialize AWS SDK clients
s3_client = boto3.client('s3')

# Configure Grype to use /tmp for any runtime caching
# The pre-downloaded DB is at /opt/grype-db (read-only)
# But Grype may need /tmp for temporary files
os.environ['XDG_CACHE_HOME'] = '/tmp/.cache'
os.environ['GRYPE_DB_CACHE_DIR'] = '/opt/grype-db'

# Ensure /tmp cache directory exists
os.makedirs('/tmp/.cache', exist_ok=True)

def lambda_handler(event, context):
    """
    Lambda handler for vulnerability detection workflow.
    
    Expected event format:
    {
        "repo_url": "https://github.com/apache/logging-log4j1.git",
        "repo_name": ""  # optional, will be extracted from URL if not provided
    }
    """
    # Configuration via environment variables
    bucket_name = os.environ['S3_BUCKET']
    output_prefix = os.environ.get('OUTPUT_PREFIX', 'scans').rstrip('/')
    
    # Get repository URL from event
    repo_url = event.get('repo_url', "https://github.com/apache/logging-log4j1.git")
    if not repo_url:
        raise ValueError("repo_url is required in the event")
    
    # Extract repo name from URL if not provided
    repo_name = event.get('repo_name')
    if not repo_name:
        # Extract from URL: https://github.com/user/repo.git -> repo
        repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '')
    
    # Create timestamp for this scan
    timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    scan_id = f"{repo_name}-{timestamp}"
    
    print(f"Starting vulnerability scan for {repo_name}...")
    print(f"Repository URL: {repo_url}")
    print(f"Scan ID: {scan_id}")
    
    # Define paths in /tmp (Lambda's writable directory)
    repo_dir = f"/tmp/{repo_name}"
    sbom_path = f"/tmp/{scan_id}.sbom.spdx.json"
    scan_json_path = f"/tmp/{scan_id}.scan.json"
    scan_parquet_path = f"/tmp/{scan_id}.scan.parquet"
    
    try:
        # Step 1: Clone the repository
        print(f"Cloning repository from {repo_url}...")
        if os.path.exists(repo_dir):
            subprocess.run(["rm", "-rf", repo_dir], check=True)
        
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, repo_dir],
            capture_output=True,
            text=True,
            check=True
        )
        print(f"Repository cloned successfully to {repo_dir}")
        
        # Step 2: Extract SBOM using Syft
        print("Extracting SBOM with Syft...")
        extract_sbom(repo_dir, sbom_path)
        print(f"SBOM extracted to {sbom_path}")
        
        # Check SBOM file size for debugging
        if os.path.exists(sbom_path):
            sbom_size = os.path.getsize(sbom_path)
            print(f"SBOM file size: {sbom_size} bytes")
        
        # Step 3: Perform vulnerability scan using Grype
        print("Performing vulnerability scan with Grype...")
        print(f"Using Grype DB at: {os.environ.get('GRYPE_DB_CACHE_DIR')}")
        
        vuln_df = perform_vuln_scan(sbom_path, scan_parquet_path, scan_json_path)
        print(f"Vulnerability scan complete. Found {len(vuln_df)} vulnerabilities")
        
        # Step 4: Upload results to S3
        s3_output_prefix = f"{output_prefix}/{scan_id}"
        result_urls = {}
        
        # Upload SBOM
        sbom_s3_key = f"{s3_output_prefix}/sbom.spdx.json"
        s3_client.upload_file(sbom_path, bucket_name, sbom_s3_key)
        result_urls['sbom'] = f"s3://{bucket_name}/{sbom_s3_key}"
        print(f"Uploaded SBOM: {result_urls['sbom']}")
        
        # Upload scan JSON
        if os.path.exists(scan_json_path):
            scan_json_s3_key = f"{s3_output_prefix}/scan.json"
            s3_client.upload_file(scan_json_path, bucket_name, scan_json_s3_key)
            result_urls['scan_json'] = f"s3://{bucket_name}/{scan_json_s3_key}"
            print(f"Uploaded scan JSON: {result_urls['scan_json']}")
        
        # Upload scan Parquet (the main output)
        scan_parquet_s3_key = f"{s3_output_prefix}/scan.parquet"
        s3_client.upload_file(scan_parquet_path, bucket_name, scan_parquet_s3_key)
        result_urls['scan_parquet'] = f"s3://{bucket_name}/{scan_parquet_s3_key}"
        print(f"Uploaded scan Parquet: {result_urls['scan_parquet']}")
        
        # Get vulnerability summary
        severity_counts = vuln_df['severity'].value_counts().to_dict() if 'severity' in vuln_df.columns else {}
        
        # Cleanup /tmp to save space for future invocations
        print("Cleaning up temporary files...")
        subprocess.run(["rm", "-rf", repo_dir], check=False)
        for tmp_file in [sbom_path, scan_json_path, scan_parquet_path]:
            if os.path.exists(tmp_file):
                os.remove(tmp_file)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'scan_id': scan_id,
                'repo_name': repo_name,
                'repo_url': repo_url,
                'timestamp': timestamp,
                'output_files': result_urls,
                'summary': {
                    'total_vulnerabilities': len(vuln_df),
                    'severity_counts': severity_counts
                }
            })
        }
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Command failed: {e.cmd}\nStdout: {e.stdout}\nStderr: {e.stderr}"
        print(error_msg)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Command execution failed',
                'details': error_msg
            })
        }
    
    except Exception as e:
        print(f"Error during vulnerability scan: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'scan_id': scan_id if 'scan_id' in locals() else None
            })
        }