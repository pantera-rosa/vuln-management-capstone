import os
import boto3
import pandas as pd
import numpy as np
from datetime import datetime
# Import the assessor module and VulnScan model from the project
from src.backend.workflow.vuln_assess import assessor
from src.backend.schemas.models import VulnScan

# Initialize AWS SDK clients once (for efficiency in warm Lambdas)
s3_client = boto3.client('s3')

def lambda_handler(event, context):
    # Configuration via environment variables
    bucket_name = os.environ['S3_BUCKET']
    input_prefix = os.environ.get('S3_INPUT_PREFIX', 'scans').rstrip('/')
    output_prefix = os.environ.get('S3_OUTPUT_PREFIX', 'assessments').rstrip('/')

    # Get repo_name from event (passed from detect step)
    repo_name = event.get('repo_name', None)

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
        
        # Get all folder names (timestamps like 20251106-012915/)
        folders = [prefix['Prefix'] for prefix in resp['CommonPrefixes']]
        # Sort to get the latest (most recent timestamp)
        latest_folder = sorted(folders)[-1]
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
    local_path = "/tmp/latest_scan.parquet"
    s3_client.download_file(bucket_name, input_key, local_path)

    # Load the scan results into a pandas DataFrame
    df = pd.read_parquet(local_path)
    
    # Print column names for debugging
    print(f"DataFrame columns: {list(df.columns)}")
    print(f"DataFrame shape: {df.shape}")
    
    # Convert DataFrame to list of dicts and clean up NaN values
    records = df.to_dict(orient='records')
    
    # Clean up each record - replace NaN with None
    cleaned_records = []
    for record in records:
        cleaned_record = {}
        for key, value in record.items():
            # Handle different types of values
            if value is None:
                cleaned_record[key] = None
            elif isinstance(value, float) and np.isnan(value):
                # Handle NaN floats
                cleaned_record[key] = None
            elif isinstance(value, str) and value == '':
                # Handle empty strings
                cleaned_record[key] = None
            elif isinstance(value, (list, dict)):
                # Keep lists and dicts as-is (like references)
                cleaned_record[key] = value
            else:
                # Keep other values as-is
                cleaned_record[key] = value
        cleaned_records.append(cleaned_record)

    # Convert each record to a VulnScan object
    findings = []
    for idx, record in enumerate(cleaned_records):
        try:
            findings.append(VulnScan(**record))
        except Exception as e:
            print(f"Error processing record {idx}: {e}")
            print(f"Record keys: {list(record.keys())}")
            print(f"Problematic values: cve_id={record.get('cve_id')}, ghsa_id={record.get('ghsa_id')}")
            raise
    
    print(f"Successfully loaded {len(findings)} vulnerability findings")

    # Run the vulnerability assessment
    assessed_df, output_paths = assessor.assess_vulns_df_and_save(findings, out_dir="/tmp/assessments")

    # Upload the resulting files to S3 under the same folder name
    result_urls = {}
    output_folder_prefix = f"{output_prefix}/{folder_name}/"
    for file_type, path in output_paths.items():
        file_name = os.path.basename(path)
        s3_key = output_folder_prefix + file_name
        s3_client.upload_file(path, bucket_name, s3_key)
        result_urls[file_type] = f"s3://{bucket_name}/{s3_key}"
        print(f"Uploaded {file_type}: {result_urls[file_type]}")

    # Prepare summary
    risk_counts = assessed_df['risk_label'].value_counts().to_dict()

    # Return a summary
    return {
        "folder": folder_name,
        "input_file": f"s3://{bucket_name}/{input_key}",
        "output_files": result_urls,
        "risk_summary": risk_counts,
        "total_findings": len(findings)
    }