import os
import subprocess
import shutil
import boto3
import zipfile
import pandas as pd
from vuln_scan import extract_sbom, perform_vuln_scan

s3_client = boto3.client('s3')
sns_client = boto3.client('sns')

def lambda_handler(event, context):
    repo_url = "https://github.com/veracode/verademo.git"
    repo_dir = "/tmp/verademo"

    # Clean old clone if exists
    if os.path.exists(repo_dir):
        shutil.rmtree(repo_dir)

    # Clone VeraDemo from GitHub
    subprocess.run(["git", "clone", repo_url, repo_dir], check=True)

    # Generate SBOM
    sbom_path = "/tmp/verademo_sbom.spdx.json"
    extract_sbom(repo_dir, output_sbom_path=sbom_path)

    # Scan SBOM
    scan_json_path = "/tmp/vuln_report.json"
    scan_parquet_path = "/tmp/vuln_report.parquet"
    vuln_df = perform_vuln_scan(sbom_path, output_scan_path=scan_json_path, output_pd_path=scan_parquet_path)

    # Upload results to S3
    results_bucket = os.environ['S3_BUCKET']
    s3_prefix = f"verademo/scans/{context.aws_request_id}"
    s3_client.upload_file(sbom_path, results_bucket, f"{s3_prefix}/sbom.spdx.json")
    s3_client.upload_file(scan_json_path, results_bucket, f"{s3_prefix}/vuln_report.json")
    s3_client.upload_file(scan_parquet_path, results_bucket, f"{s3_prefix}/vuln_report.parquet")

    # Notify via SNS
    #if 'SNS_TOPIC_ARN' in os.environ:
        #sns_topic = os.environ['SNS_TOPIC_ARN']
        #msg = create_summary_message(vuln_df, s3_prefix, results_bucket)
        #sns_client.publish(TopicArn=sns_topic, Subject="Vulnerability Scan Complete", Message=msg)

    return {"status": "completed", "s3_output": f"s3://{results_bucket}/{s3_prefix}/"}

def create_summary_message(vuln_df, prefix, bucket):
    total = len(vuln_df)
    summary = f"Total vulnerabilities: {total}\n"
    if total:
        sev_count = vuln_df['severity'].value_counts().to_dict()
        summary += "Severity breakdown: " + ", ".join(f"{k}: {v}" for k, v in sev_count.items()) + "\n"
    summary += f"Results stored in s3://{bucket}/{prefix}/"
    return summary
