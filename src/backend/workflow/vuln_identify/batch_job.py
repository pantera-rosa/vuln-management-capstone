#!/usr/bin/env python3
"""
AWS Batch job script for Vulnerability Code Identification.

This script is the entry point for the Batch job container.
It reads configuration from environment variables and runs the full
vuln_code_identify workflow without time constraints.
"""

import os
import sys
import shutil
import boto3
import pandas as pd
import numpy as np
from datetime import datetime

# Add the current directory to Python path
sys.path.insert(0, os.environ.get('WORKDIR', '/app'))

# Import after path is set
from src.backend.workflow.vuln_identify.vuln_code_identify import vuln_code_identify
from src.backend.schemas.models import VulnScan, VulnCodeIdentification

# Initialize AWS SDK clients
s3_client = boto3.client('s3')


def main():
    """
    Main entry point for Batch job.
    
    Environment Variables:
        S3_BUCKET: S3 bucket name (required)
        S3_INPUT_PREFIX: Input prefix (default: 'scans')
        S3_OUTPUT_PREFIX: Output prefix (default: 'identifications')
        FOLDER_NAME: Specific folder to process (optional, uses latest if not set)
        GH_TOKEN: GitHub personal access token (required)
        SEMGREP_APP_TOKEN: Semgrep app token (optional)
        SEMGREP_NUM_JOBS: Number of parallel semgrep jobs (default: 4)
        ENABLE_DATAFLOW_TRACES: Enable dataflow traces (default: 'false')
    """
    print("=" * 60)
    print("AWS Batch - Vulnerability Code Identification")
    print("=" * 60)
    print(f"Start time: {datetime.utcnow().isoformat()}Z")
    
    # Set HOME for git and gh CLI
    os.environ['HOME'] = '/tmp'
    
    # Ensure /usr/local/bin is in PATH
    current_path = os.environ.get('PATH', '')
    if '/usr/local/bin' not in current_path:
        os.environ['PATH'] = f"/usr/local/bin:{current_path}"
    
    # Configuration
    bucket_name = os.environ['S3_BUCKET']
    input_prefix = os.environ.get('S3_INPUT_PREFIX', 'scans').rstrip('/')
    output_prefix = os.environ.get('S3_OUTPUT_PREFIX', 'identifications').rstrip('/')
    folder_name = os.environ.get('FOLDER_NAME', '')
    
    # Validate GitHub token
    gh_token = os.environ.get('GH_TOKEN', '')
    if not gh_token:
        raise ValueError("GH_TOKEN environment variable is required")
    
    # Setup GitHub authentication
    _setup_github_auth(gh_token)
    
    print(f"Configuration:")
    print(f"  S3 Bucket: {bucket_name}")
    print(f"  Input Prefix: {input_prefix}")
    print(f"  Output Prefix: {output_prefix}")
    print(f"  Folder: {folder_name or 'latest'}")
    
    # Determine which folder to process
    if not folder_name:
        folder_name = _get_latest_folder(bucket_name, input_prefix)
    
    scan_prefix = f"{input_prefix}/{folder_name}/"
    print(f"\nProcessing: s3://{bucket_name}/{scan_prefix}")
    
    # Download input parquet file
    input_key = _find_parquet_file(bucket_name, scan_prefix)
    local_input_path = "/tmp/input_scan.parquet"
    
    print(f"Downloading: s3://{bucket_name}/{input_key}")
    s3_client.download_file(bucket_name, input_key, local_input_path)
    
    # Load and prepare data
    vuln_scan_df = pd.read_parquet(local_input_path)
    print(f"Loaded DataFrame: {vuln_scan_df.shape}")
    
    # Handle column mapping (for different scan outputs)
    vuln_scan_df = _normalize_columns(vuln_scan_df)
    
    print(f"Unfixed vulnerabilities: {vuln_scan_df['fixed_version'].isnull().sum()}")
    
    # Setup working directories
    dep_repos_dir = "/tmp/repos"
    output_scans_dir = "/tmp/scans_raw"
    output_scans_pd_dir = "/tmp/scans_pd"
    output_pd_path = "/tmp/vuln_code_identification.parquet"
    
    for dir_path in [dep_repos_dir, output_scans_dir, output_scans_pd_dir]:
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)
        os.makedirs(dir_path, exist_ok=True)
    
    if os.path.exists(output_pd_path):
        os.remove(output_pd_path)
    
    # Get semgrep configuration from environment variables
    enable_dataflow = os.environ.get('ENABLE_DATAFLOW_TRACES', 'false').lower() == 'true'
    semgrep_jobs = int(os.environ.get('SEMGREP_NUM_JOBS', '10'))
    semgrep_timeout = int(os.environ.get('SEMGREP_TIMEOUT', '300'))  # 5 minutes per rule
    max_file_size = int(os.environ.get('SEMGREP_MAX_FILE_SIZE', '1000000'))  # 1MB
    
    print(f"Semgrep configuration:")
    print(f"  Jobs: {semgrep_jobs}")
    print(f"  Dataflow traces: {enable_dataflow}")
    print(f"  Timeout per rule: {semgrep_timeout}s")
    print(f"  Max file size: {max_file_size / 1_000_000:.1f}MB")
    
    # Run the identification
    print("\n" + "=" * 60)
    print("Starting vulnerability code identification...")
    print("=" * 60)
    
    start_time = datetime.utcnow()
    
    identified_df = vuln_code_identify(
        vuln_scan_df=vuln_scan_df,
        dep_repos_root_dir_path=dep_repos_dir,
        output_scans_dir_path=output_scans_dir,
        output_scans_pd_dir_path=output_scans_pd_dir,
        output_pd_path=output_pd_path,
        semgrep_jobs=semgrep_jobs,
        enable_dataflow_traces=enable_dataflow,
        semgrep_timeout=semgrep_timeout,
        max_file_size=max_file_size
    )
    
    end_time = datetime.utcnow()
    duration = (end_time - start_time).total_seconds()
    
    print(f"\nIdentification complete!")
    print(f"Duration: {duration:.2f} seconds ({duration/60:.2f} minutes)")
    print(f"Result shape: {identified_df.shape}")
    
    # Upload results to S3
    print("\n" + "=" * 60)
    print("Uploading results to S3...")
    print("=" * 60)
    
    result_urls = _upload_results(
        bucket_name, output_prefix, folder_name,
        output_pd_path, output_scans_dir, output_scans_pd_dir
    )
    
    # Generate summary
    summary = _generate_summary(identified_df)
    
    # Write job summary
    print("\n" + "=" * 60)
    print("Job Summary")
    print("=" * 60)
    print(f"Folder: {folder_name}")
    print(f"Input: s3://{bucket_name}/{input_key}")
    print(f"Output: {result_urls['identification']}")
    print(f"Duration: {duration:.2f} seconds")
    print(f"Total vulnerabilities: {summary['total_vulnerabilities']}")
    print(f"Unfixed: {summary['unfixed_vulnerabilities']}")
    print(f"With code path: {summary['vulnerabilities_with_code_path']}")
    print(f"End time: {datetime.utcnow().isoformat()}Z")
    
    # Write summary to S3
    summary_data = {
        "folder": folder_name,
        "input_file": f"s3://{bucket_name}/{input_key}",
        "output_files": result_urls,
        "summary": summary,
        "duration_seconds": duration,
        "start_time": start_time.isoformat() + "Z",
        "end_time": end_time.isoformat() + "Z"
    }
    
    import json
    summary_path = "/tmp/job_summary.json"
    with open(summary_path, 'w') as f:
        json.dump(summary_data, f, indent=2)
    
    summary_key = f"{output_prefix}/{folder_name}/job_summary.json"
    s3_client.upload_file(summary_path, bucket_name, summary_key)
    print(f"Summary uploaded: s3://{bucket_name}/{summary_key}")
    
    print("\nJob completed successfully!")
    return 0


def _setup_github_auth(gh_token: str):
    """Setup GitHub CLI authentication."""
    os.environ['GH_TOKEN'] = gh_token
    
    import subprocess
    subprocess.run(
        ['git', 'config', '--global', 'credential.helper', 'store'],
        check=False, capture_output=True
    )
    subprocess.run(
        ['git', 'config', '--global', 
         f'url.https://oauth2:{gh_token}@github.com/.insteadOf', 
         'https://github.com/'],
        check=False, capture_output=True
    )
    print("GitHub authentication configured")


def _get_latest_folder(bucket_name: str, input_prefix: str) -> str:
    """Find the latest folder (by timestamp) in the input prefix."""
    resp = s3_client.list_objects_v2(
        Bucket=bucket_name,
        Prefix=f"{input_prefix}/",
        Delimiter='/'
    )
    
    if 'CommonPrefixes' not in resp or len(resp['CommonPrefixes']) == 0:
        raise RuntimeError(f"No folders found in s3://{bucket_name}/{input_prefix}/")
    
    folders = [p['Prefix'] for p in resp['CommonPrefixes']]
    latest = sorted(folders)[-1]
    return latest.rstrip('/').split('/')[-1]


def _find_parquet_file(bucket_name: str, prefix: str) -> str:
    """Find the newest parquet file in the given prefix."""
    resp = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    
    if 'Contents' not in resp:
        raise RuntimeError(f"No files found in s3://{bucket_name}/{prefix}")
    
    parquet_files = [obj for obj in resp['Contents'] if obj['Key'].endswith('.parquet')]
    if not parquet_files:
        raise RuntimeError(f"No parquet files in s3://{bucket_name}/{prefix}")
    
    latest = max(parquet_files, key=lambda x: x['LastModified'])
    return latest['Key']


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize column names to match expected schema."""
    column_mapping = {
        'id': 'cve_id',
        'related_id': 'ghsa_id',
        'cvss_v4_vector': 'cvss_v4_score'
    }
    
    for old_col, new_col in column_mapping.items():
        if old_col in df.columns:
            df = df.rename(columns={old_col: new_col})
            print(f"Renamed: {old_col} -> {new_col}")
    
    required_columns = {
        'cve_id': '',
        'ghsa_id': '',
        'source_code_location': None,
        'cwe_id': None,
        'cwe_name': None,
        'cvss_v4_score': None
    }
    
    for col, default in required_columns.items():
        if col not in df.columns:
            df[col] = default
            print(f"Added missing column: {col}")
    
    return df


def _upload_results(bucket_name: str, output_prefix: str, folder_name: str,
                   main_output_path: str, raw_scans_dir: str, pd_scans_dir: str) -> dict:
    """Upload all result files to S3."""
    result_urls = {}
    output_folder = f"{output_prefix}/{folder_name}/"
    
    # Upload main identification results
    main_key = f"{output_folder}vuln_code_identification.parquet"
    s3_client.upload_file(main_output_path, bucket_name, main_key)
    result_urls['identification'] = f"s3://{bucket_name}/{main_key}"
    print(f"Uploaded: {result_urls['identification']}")
    
    # Upload raw JSON scans
    scan_count = 0
    if os.path.exists(raw_scans_dir):
        for filename in os.listdir(raw_scans_dir):
            if filename.endswith('.json'):
                local_path = os.path.join(raw_scans_dir, filename)
                s3_key = f"{output_folder}scans_raw/{filename}"
                s3_client.upload_file(local_path, bucket_name, s3_key)
                scan_count += 1
    
    # Upload processed parquet scans
    if os.path.exists(pd_scans_dir):
        for filename in os.listdir(pd_scans_dir):
            if filename.endswith('.parquet'):
                local_path = os.path.join(pd_scans_dir, filename)
                s3_key = f"{output_folder}scans_pd/{filename}"
                s3_client.upload_file(local_path, bucket_name, s3_key)
                scan_count += 1
    
    result_urls['scan_results_count'] = scan_count
    print(f"Uploaded {scan_count} scan result files")
    
    return result_urls


def _generate_summary(df: pd.DataFrame) -> dict:
    """Generate summary statistics."""
    return {
        "total_vulnerabilities": int(len(df)),
        "unfixed_vulnerabilities": int(df['fixed_version'].isnull().sum()),
        "fixed_vulnerabilities": int(df['fixed_version'].notnull().sum()),
        "vulnerabilities_with_code_path": int(df['path'].notnull().sum()) if 'path' in df.columns else 0
    }


if __name__ == "__main__":
    sys.exit(main())