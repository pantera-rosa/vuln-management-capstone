import os
import boto3
import pandas as pd
import numpy as np
from datetime import datetime

# Import the correct model - vuln_identify outputs VulnCodeIdentification
from src.backend.schemas.models import VulnCodeIdentification
from src.backend.workflow.vuln_assess import assessor

# Initialize AWS SDK clients once (for efficiency in warm Lambdas)
s3_client = boto3.client('s3')

def lambda_handler(event, context):
    """
    Lambda handler for vulnerability assessment workflow.
    Reads VulnCodeIdentification results from vuln_identify workflow,
    enriches with EPSS/KEV data, calculates risk scores, and saves assessments.
    """
    # Configuration via environment variables
    bucket_name = os.environ['S3_BUCKET']
    input_prefix = os.environ.get('S3_INPUT_PREFIX', 'identifications').rstrip('/')
    output_prefix = os.environ.get('S3_OUTPUT_PREFIX', 'assessments').rstrip('/')
    
    print("="*60)
    print("Vulnerability Assessment Workflow")
    print("="*60)
    print(f"S3 Bucket: {bucket_name}")
    print(f"Input Prefix: {input_prefix}")
    print(f"Output Prefix: {output_prefix}")
    
    # Check if a specific folder was provided in the event
    folder_name = event.get('folder')
    
    if folder_name:
        # Use the provided folder name directly
        scan_prefix = f"{input_prefix}/{folder_name}/"
        print(f"Using specified folder: {folder_name}")
    else:
        # List all folders under the input prefix to find the latest one
        print(f"Finding latest folder in s3://{bucket_name}/{input_prefix}/")
        resp = s3_client.list_objects_v2(
            Bucket=bucket_name, 
            Prefix=f"{input_prefix}/",
            Delimiter='/'
        )
        
        if 'CommonPrefixes' not in resp or len(resp['CommonPrefixes']) == 0:
            raise RuntimeError(f"No scan folders found in s3://{bucket_name}/{input_prefix}/")
        
        # Get all folder names (timestamps like 20251124-012915/)
        folders = [prefix['Prefix'] for prefix in resp['CommonPrefixes']]
        # Sort to get the latest (most recent timestamp)
        latest_folder = sorted(folders)[-1]
        scan_prefix = latest_folder
        folder_name = latest_folder.rstrip('/').split('/')[-1]
        print(f"Found latest folder: {folder_name}")
    
    print(f"Processing scan from: s3://{bucket_name}/{scan_prefix}")
    
    # Look specifically for vuln_code_identification.parquet
    expected_filename = "vuln_code_identification.parquet"
    input_key = f"{scan_prefix}{expected_filename}"
    
    print(f"Looking for: s3://{bucket_name}/{input_key}")
    
    # Check if the expected file exists
    try:
        head_response = s3_client.head_object(Bucket=bucket_name, Key=input_key)
        file_size = head_response['ContentLength']
        last_modified = head_response['LastModified']
        print(f"✓ Found expected file!")
        print(f"  File size: {file_size / 1024 / 1024:.2f} MB")
        print(f"  Last modified: {last_modified}")
    except s3_client.exceptions.NoSuchKey:
        # File doesn't exist - list what files ARE available
        print(f"❌ Expected file not found: {expected_filename}")
        print(f"Listing available files in s3://{bucket_name}/{scan_prefix}")
        
        resp = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=scan_prefix)
        if 'Contents' not in resp or len(resp['Contents']) == 0:
            raise RuntimeError(f"No files found in s3://{bucket_name}/{scan_prefix}")
        
        print(f"Available files:")
        for obj in resp['Contents']:
            relative_path = obj['Key'][len(scan_prefix):]
            print(f"  - {relative_path} ({obj['Size'] / 1024:.1f} KB)")
        
        # Try to find any parquet file at root level
        root_parquet_files = [
            obj for obj in resp['Contents']
            if obj['Key'].endswith('.parquet') and '/' not in obj['Key'][len(scan_prefix):]
        ]
        
        if not root_parquet_files:
            raise RuntimeError(
                f"Expected file '{expected_filename}' not found and no other root-level parquet files available.\n"
                f"The vuln_identify workflow should create '{expected_filename}' in the folder.\n"
                f"Available files: {[obj['Key'] for obj in resp['Contents']]}"
            )
        
        # Use the first root-level parquet file found
        input_key = root_parquet_files[0]['Key']
        print(f"⚠️  Using alternative file: {input_key}")

    # Download the Parquet file to /tmp
    local_path = "/tmp/vuln_identify_results.parquet"
    print(f"Downloading to {local_path}...")
    s3_client.download_file(bucket_name, input_key, local_path)
    print(f"✓ Download complete")

    # Load the scan results into a pandas DataFrame
    print("Loading Parquet file into DataFrame...")
    df = pd.read_parquet(local_path)
    
    # Print column info for debugging
    print(f"DataFrame shape: {df.shape} (rows × columns)")
    print(f"DataFrame columns ({len(df.columns)}):")
    
    # Show first 20 columns
    cols_to_show = min(20, len(df.columns))
    for i, col in enumerate(list(df.columns)[:cols_to_show]):
        print(f"  {i+1:2d}. {col}")
    if len(df.columns) > cols_to_show:
        print(f"  ... and {len(df.columns) - cols_to_show} more columns")
    
    # Check for required columns
    required_cols = ['cve_id', 'package_name', 'package_version']
    missing_cols = [col for col in required_cols if col not in df.columns]
    
    if missing_cols:
        print(f"\n❌ ERROR: Missing required columns!")
        print(f"   Required: {required_cols}")
        print(f"   Missing: {missing_cols}")
        print(f"   File loaded: {input_key}")
        print(f"\nThis file may be from the wrong workflow stage.")
        print(f"Expected: vuln_code_identification.parquet with vulnerability metadata")
        print(f"Got: File with only {list(df.columns)[:10]} ...")
        
        raise RuntimeError(
            f"Missing required columns: {missing_cols}\n"
            f"File: {input_key}\n"
            f"Available columns: {list(df.columns)}\n"
            f"This file may not be from vuln_identify workflow."
        )
    
    print(f"✓ All required columns present: {required_cols}")
    
    # Show sample data
    if len(df) > 0:
        print(f"\nSample record:")
        sample = df.iloc[0]
        print(f"  CVE ID: {sample.get('cve_id', 'N/A')}")
        print(f"  Package: {sample.get('package_name', 'N/A')} @ {sample.get('package_version', 'N/A')}")
        print(f"  Severity: {sample.get('severity', 'N/A')}")
        if 'path' in sample:
            print(f"  Code: {sample.get('path', 'N/A')}:{sample.get('start_line', 'N/A')}")
    
    # Convert DataFrame to list of dicts and clean up NaN values
    print(f"\nConverting {len(df)} records to VulnCodeIdentification objects...")
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
                # Handle empty strings - keep as empty string for path/filename
                cleaned_record[key] = None if key not in ['path', 'filename'] else value
            elif isinstance(value, (list, dict)):
                # Keep lists and dicts as-is (like references, dataflow traces)
                cleaned_record[key] = value
            else:
                # Keep other values as-is
                cleaned_record[key] = value
        cleaned_records.append(cleaned_record)

    # Convert each record to a VulnCodeIdentification object
    findings = []
    errors = []
    
    for idx, record in enumerate(cleaned_records):
        try:
            # Create VulnCodeIdentification object
            finding = VulnCodeIdentification(**record)
            findings.append(finding)
        except Exception as e:
            error_msg = f"Record {idx}: {str(e)}"
            errors.append(error_msg)
            # Only print first few errors to avoid cluttering logs
            if len(errors) <= 5:
                print(f"⚠️  {error_msg}")
                if len(errors) <= 2:
                    print(f"   Keys: {list(record.keys())[:10]}...")
                    print(f"   Sample: cve_id={record.get('cve_id')}, pkg={record.get('package_name')}")
    
    if errors:
        print(f"\n⚠️  {len(errors)} records failed to parse (out of {len(cleaned_records)})")
        if len(errors) == len(cleaned_records):
            print(f"First error: {errors[0]}")
            raise RuntimeError(f"All records failed to parse!")
        elif len(errors) > len(cleaned_records) * 0.5:
            print(f"Warning: More than 50% of records failed to parse")
    
    print(f"✓ Successfully loaded {len(findings)} vulnerability findings")

    # Run the vulnerability assessment
    print("\n" + "="*60)
    print("Running vulnerability assessment...")
    print("  - Fetching EPSS scores from FIRST.org")
    print("  - Checking CISA KEV catalog")
    print("  - Calculating risk scores")
    print("="*60)
    
    assessed_df, output_paths = assessor.assess_vulns_df_and_save(
        findings, 
        out_dir="/tmp/assessments"
    )
    
    print(f"\n✓ Assessment complete!")
    print(f"  Total findings: {len(assessed_df)}")
    
    # Print risk distribution
    if 'risk_label' in assessed_df.columns:
        risk_counts = assessed_df['risk_label'].value_counts().to_dict()
        print(f"\n  Risk distribution:")
        for label in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = risk_counts.get(label, 0)
            pct = (count / len(assessed_df) * 100) if len(assessed_df) > 0 else 0
            print(f"    {label}: {count:3d} ({pct:5.1f}%)")
    
    # KEV count
    kev_count = int(assessed_df['kev'].sum()) if 'kev' in assessed_df.columns else 0
    if kev_count > 0:
        print(f"\n  ⚠️  KEV-listed (actively exploited): {kev_count}")

    # Upload the resulting files to S3
    print("\n" + "="*60)
    print("Uploading results to S3...")
    result_urls = {}
    output_folder_prefix = f"{output_prefix}/{folder_name}/"
    
    for file_type, path in output_paths.items():
        file_name = os.path.basename(path)
        s3_key = output_folder_prefix + file_name
        print(f"  Uploading {file_type}: {file_name}...")
        s3_client.upload_file(path, bucket_name, s3_key)
        result_urls[file_type] = f"s3://{bucket_name}/{s3_key}"
        print(f"    ✓ {result_urls[file_type]}")

    # Prepare detailed summary
    risk_counts = assessed_df['risk_label'].value_counts().to_dict() if 'risk_label' in assessed_df.columns else {}
    
    print("\n" + "="*60)
    print("✓ ASSESSMENT COMPLETE")
    print("="*60)
    print(f"Input:  s3://{bucket_name}/{input_key}")
    print(f"Folder: {folder_name}")
    print(f"Total findings assessed: {len(assessed_df)}")
    print(f"KEV-listed vulnerabilities: {kev_count}")
    if errors:
        print(f"Parse errors: {len(errors)}")
    print("="*60)

    # Return a summary
    return {
        "status": "success",
        "folder": folder_name,
        "input_file": f"s3://{bucket_name}/{input_key}",
        "output_files": result_urls,
        "risk_summary": risk_counts,
        "total_findings": len(findings),
        "successfully_assessed": len(assessed_df),
        "kev_count": kev_count,
        "parse_errors": len(errors)
    }