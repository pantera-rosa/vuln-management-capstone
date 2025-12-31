import os
import sys
import shutil
import boto3
import pandas as pd
import numpy as np
from datetime import datetime

# Add the Lambda task root to Python path
sys.path.insert(0, os.environ.get('LAMBDA_TASK_ROOT', '/var/task'))

# Now import after path is set
from src.backend.workflow.vuln_identify.vuln_code_identify import vuln_code_identify
from src.backend.schemas.models import VulnScan, VulnCodeIdentification

# Initialize AWS SDK clients once (for efficiency in warm Lambdas)
s3_client = boto3.client('s3')


def lambda_handler(event, context):
    """
    Lambda handler for vulnerability code identification.
    
    Reads vulnerability scan results from S3, performs code identification
    using Semgrep on unfixed vulnerabilities, and uploads results back to S3.
    
    Environment Variables:
        S3_BUCKET: S3 bucket name
        S3_INPUT_PREFIX: Prefix for input scan files (default: 'scans')
        S3_OUTPUT_PREFIX: Prefix for output identification files (default: 'identifications')
        GH_TOKEN: GitHub personal access token for gh CLI
        SEMGREP_APP_TOKEN: (optional) Semgrep app token for enhanced results
    
    Event Parameters:
        folder: (optional) Specific folder name to process. If not provided, uses latest.
        skip_fork: (optional) If True, skip forking repos (useful for testing)
    """
    print("Starting vulnerability code identification...")
    
    # Configuration via environment variables
    bucket_name = os.environ['S3_BUCKET']
    input_prefix = os.environ.get('S3_INPUT_PREFIX', 'scans').rstrip('/')
    output_prefix = os.environ.get('S3_OUTPUT_PREFIX', 'identifications').rstrip('/')
    
    # Validate required environment variables
    gh_token = os.environ.get('GH_TOKEN', '')
    if not gh_token:
        raise ValueError("GH_TOKEN environment variable is required but not set")
    
    # Set up GitHub authentication
    _setup_github_auth(gh_token)
    
    # Check if a specific folder was provided in the event
    folder_name = event.get('folder')
    
    if folder_name:
        # Use the provided folder name directly
        scan_prefix = f"{input_prefix}/{folder_name}/"
    else:
        # List all folders under the input prefix to find the latest one
        resp = s3_client.list_objects_v2(
            Bucket=bucket_name, 
            Prefix=f"{input_prefix}/",
            Delimiter='/'
        )
        
        if 'CommonPrefixes' not in resp or len(resp['CommonPrefixes']) == 0:
            raise RuntimeError(f"No scan folders found in s3://{bucket_name}/{input_prefix}/")
        
        # Get all folder names (format: {repo_name}-{timestamp}/)
        folders = [prefix['Prefix'] for prefix in resp['CommonPrefixes']]
        # Sort by the timestamp portion (last part after splitting by '-') to get the most recent
        # Extract timestamp from folder name like "juice-shop-20251211-050000" -> "20251211-050000"
        def get_timestamp(folder_path):
            folder_name = folder_path.rstrip('/').split('/')[-1]
            # Split by '-' and take the last 2 parts (date and time)
            parts = folder_name.split('-')
            if len(parts) >= 2:
                return '-'.join(parts[-2:])  # Returns "20251211-050000"
            return folder_name

        latest_folder = sorted(folders, key=get_timestamp)[-1]
        scan_prefix = latest_folder
        folder_name = latest_folder.rstrip('/').split('/')[-1]
    
    print(f"Processing scan from: s3://{bucket_name}/{scan_prefix}")
    
    # List objects under the prefix to find scan files
    resp = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=scan_prefix)
    if 'Contents' not in resp or len(resp['Contents']) == 0:
        raise RuntimeError(f"No scan result files found in s3://{bucket_name}/{scan_prefix}")

    # Find the newest Parquet file (by LastModified timestamp)
    objects = [obj for obj in resp['Contents'] if obj['Key'].endswith(".parquet")]
    if not objects:
        raise RuntimeError(f"No Parquet scan files found in s3://{bucket_name}/{scan_prefix}")
    latest_obj = max(objects, key=lambda x: x['LastModified'])
    input_key = latest_obj['Key']

    print(f"Processing file: s3://{bucket_name}/{input_key}")

    # Download the Parquet scan result to /tmp
    local_input_path = "/tmp/latest_scan.parquet"
    s3_client.download_file(bucket_name, input_key, local_input_path)

    # Load the scan results into a pandas DataFrame
    vuln_scan_df = pd.read_parquet(local_input_path)
    
    # Print column names for debugging
    print(f"DataFrame columns: {list(vuln_scan_df.columns)}")
    print(f"DataFrame shape: {vuln_scan_df.shape}")
    print(f"Number of unfixed vulnerabilities: {vuln_scan_df['fixed_version'].isnull().sum()}")
    
    # Set up local directories for processing
    dep_repos_dir = "/tmp/repos"
    output_scans_dir = "/tmp/scans_raw"
    output_scans_pd_dir = "/tmp/scans_pd"
    output_pd_path = "/tmp/vuln_code_identification.parquet"
    
    # Clean up any existing directories
    for dir_path in [dep_repos_dir, output_scans_dir, output_scans_pd_dir]:
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)
        os.makedirs(dir_path, exist_ok=True)
    
    # Remove existing output file if it exists (to force reprocessing)
    if os.path.exists(output_pd_path):
        os.remove(output_pd_path)
    
    print("Running vulnerability code identification...")
    
    # Run the vulnerability code identification
    identified_df = vuln_code_identify(
        vuln_scan_df=vuln_scan_df,
        dep_repos_root_dir_path=dep_repos_dir,
        output_scans_dir_path=output_scans_dir,
        output_scans_pd_dir_path=output_scans_pd_dir,
        output_pd_path=output_pd_path
    )
    
    print(f"Vulnerability code identification complete. Result shape: {identified_df.shape}")
    
    # Upload results to S3
    result_urls = {}
    output_folder_prefix = f"{output_prefix}/{folder_name}/"
    
    # Upload main identification results
    main_s3_key = f"{output_folder_prefix}vuln_code_identification.parquet"
    s3_client.upload_file(output_pd_path, bucket_name, main_s3_key)
    result_urls['identification'] = f"s3://{bucket_name}/{main_s3_key}"
    print(f"Uploaded identification results: {result_urls['identification']}")
    
    # Upload individual scan results (raw JSON and Parquet)
    scan_results_uploaded = 0
    
    # Upload raw scan JSONs
    if os.path.exists(output_scans_dir):
        for filename in os.listdir(output_scans_dir):
            if filename.endswith('.json'):
                local_path = os.path.join(output_scans_dir, filename)
                s3_key = f"{output_folder_prefix}scans_raw/{filename}"
                s3_client.upload_file(local_path, bucket_name, s3_key)
                scan_results_uploaded += 1
    
    # Upload scan Parquet files
    if os.path.exists(output_scans_pd_dir):
        for filename in os.listdir(output_scans_pd_dir):
            if filename.endswith('.parquet'):
                local_path = os.path.join(output_scans_pd_dir, filename)
                s3_key = f"{output_folder_prefix}scans_pd/{filename}"
                s3_client.upload_file(local_path, bucket_name, s3_key)
                scan_results_uploaded += 1
    
    result_urls['scan_results_count'] = scan_results_uploaded
    print(f"Uploaded {scan_results_uploaded} individual scan result files")
    
    # Calculate summary statistics
    total_vulns = len(identified_df)
    unfixed_vulns = identified_df['fixed_version'].isnull().sum()
    fixed_vulns = identified_df['fixed_version'].notnull().sum()
    
    # Count vulnerabilities with code path identified
    if 'path' in identified_df.columns:
        vulns_with_code_path = identified_df['path'].notnull().sum()
    else:
        vulns_with_code_path = 0
    
    summary = {
        "total_vulnerabilities": int(total_vulns),
        "unfixed_vulnerabilities": int(unfixed_vulns),
        "fixed_vulnerabilities": int(fixed_vulns),
        "vulnerabilities_with_code_path": int(vulns_with_code_path)
    }
    
    # Clean up temporary directories to free space
    for dir_path in [dep_repos_dir, output_scans_dir, output_scans_pd_dir]:
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)
    
    print(f"Lambda execution complete. Summary: {summary}")
    
    # Return a summary
    return {
        "folder": folder_name,
        "input_file": f"s3://{bucket_name}/{input_key}",
        "output_files": result_urls,
        "summary": summary,
        "total_findings": total_vulns
    }


def _setup_github_auth(gh_token: str):
    """
    Set up GitHub CLI authentication using the provided token.
    
    Args:
        gh_token: GitHub personal access token
    """
    # Set the GH_TOKEN environment variable for gh CLI
    os.environ['GH_TOKEN'] = gh_token
    
    # Configure git to use the token for authentication
    # This helps with git clone operations
    import subprocess
    
    # Set up git credential helper to use the token
    subprocess.run(
        ['git', 'config', '--global', 'credential.helper', 'store'],
        check=False,
        capture_output=True
    )
    
    # Configure git to use the token in the URL
    subprocess.run(
        ['git', 'config', '--global', 'url.https://oauth2:{}@github.com/.insteadOf'.format(gh_token), 'https://github.com/'],
        check=False,
        capture_output=True
    )
    
    print("GitHub authentication configured")