"""
Run vulnerability code identification for unfixed vulnerabilities.
Can run standalone or be imported as a library.
"""

from __future__ import annotations
from typing import Dict, Any, Optional, Tuple
import argparse
import pandas as pd
import os
import json
import boto3
from datetime import datetime
from src.backend.utils.cmd import run_cmd, run_cmd_and_parse_output
from src.backend.utils.df import append_df, save_df
from dotenv import load_dotenv
import numpy as np

load_dotenv()

GH_TOKEN = os.environ.get("GH_TOKEN", "")
SEMGREP_APP_TOKEN = os.environ.get("SEMGREP_APP_TOKEN", "")
GITHUB_ORG_NAME = "Vuln-Guard"

# Initialize S3 client (will be None if not using S3)
_s3_client = None

def _get_s3_client():
    """Lazy initialization of S3 client."""
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client('s3')
    return _s3_client


def _download_from_s3(s3_bucket: str, s3_key: str, local_path: str) -> bool:
    """
    Download a file from S3.
    
    Args:
        s3_bucket: S3 bucket name
        s3_key: S3 object key (path in bucket)
        local_path: Local path to save the downloaded file
    
    Returns:
        True if successful, False otherwise
    """
    try:
        s3_client = _get_s3_client()
        print(f"Downloading s3://{s3_bucket}/{s3_key} to {local_path}...")
        s3_client.download_file(s3_bucket, s3_key, local_path)
        print(f"✓ Downloaded {local_path}")
        return True
    except Exception as e:
        print(f"⚠️  Failed to download from S3: {e}")
        return False


def _upload_to_s3(local_path: str, s3_bucket: str, s3_key: str) -> Optional[str]:
    """
    Upload a file to S3.
    
    Args:
        local_path: Local file path to upload
        s3_bucket: S3 bucket name
        s3_key: S3 object key (path in bucket)
    
    Returns:
        S3 URI of uploaded file, or None if upload failed
    """
    try:
        s3_client = _get_s3_client()
        s3_client.upload_file(local_path, s3_bucket, s3_key)
        s3_uri = f"s3://{s3_bucket}/{s3_key}"
        print(f"✓ Uploaded to {s3_uri}")
        return s3_uri
    except Exception as e:
        print(f"⚠️  Failed to upload {local_path} to S3: {e}")
        return None


def _extract_timestamp_from_folder(folder_path: str) -> datetime:
    """
    Extract timestamp from folder name with format: name-YYYYMMDD-HHMMSS
    
    Args:
        folder_path: S3 folder path
    
    Returns:
        datetime object, or datetime.min if parsing fails
    """
    folder_name = folder_path.rstrip('/').split('/')[-1]
    # Extract the timestamp part (last two parts: YYYYMMDD-HHMMSS)
    parts = folder_name.split('-')
    if len(parts) >= 2:
        try:
            # Combine last two parts: e.g., "20251202" + "010250"
            timestamp_str = parts[-2] + parts[-1]
            return datetime.strptime(timestamp_str, "%Y%m%d%H%M%S")
        except (ValueError, IndexError):
            return datetime.min
    return datetime.min


def _find_latest_scan_in_s3(s3_bucket: str, s3_input_prefix: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Find the latest scan folder and parquet file in S3.
    Sorts folders by timestamp extracted from folder name (format: name-YYYYMMDD-HHMMSS).
    
    Args:
        s3_bucket: S3 bucket name
        s3_input_prefix: S3 prefix to search (e.g., "scans")
    
    Returns:
        Tuple of (folder_name, s3_key) or (None, None) if not found
    """
    try:
        s3_client = _get_s3_client()
        
        # List all folders under the prefix
        resp = s3_client.list_objects_v2(
            Bucket=s3_bucket,
            Prefix=f"{s3_input_prefix}/",
            Delimiter='/'
        )
        
        if 'CommonPrefixes' not in resp or len(resp['CommonPrefixes']) == 0:
            print(f"No scan folders found in s3://{s3_bucket}/{s3_input_prefix}/")
            return None, None
        
        # Get all folder names and sort by timestamp to find latest
        folders = [prefix['Prefix'] for prefix in resp['CommonPrefixes']]
        latest_folder = max(folders, key=_extract_timestamp_from_folder)
        folder_name = latest_folder.rstrip('/').split('/')[-1]
        
        print(f"Found latest scan folder: {folder_name}")
        
        # Look for parquet files in this folder
        resp = s3_client.list_objects_v2(
            Bucket=s3_bucket,
            Prefix=latest_folder
        )
        
        if 'Contents' not in resp:
            print(f"No files found in {latest_folder}")
            return folder_name, None
        
        # Find parquet files (prefer ones at root level, not in subdirectories)
        parquet_files = [
            obj for obj in resp['Contents'] 
            if obj['Key'].endswith('.parquet')
        ]
        
        if not parquet_files:
            print(f"No parquet files found in {latest_folder}")
            return folder_name, None
        
        # Prefer files at root level
        root_files = [
            obj for obj in parquet_files
            if '/' not in obj['Key'][len(latest_folder):]
        ]
        
        if root_files:
            latest_file = max(root_files, key=lambda x: x['LastModified'])
        else:
            latest_file = max(parquet_files, key=lambda x: x['LastModified'])
        
        print(f"Found scan file: {latest_file['Key']}")
        return folder_name, latest_file['Key']
        
    except Exception as e:
        print(f"Error finding latest scan in S3: {e}")
        return None, None


def load_scan_results(
    input_path: str = None,
    s3_bucket: str = None,
    s3_key: str = None,
    s3_input_prefix: str = None,
    local_download_path: str = "/tmp/scan_results.parquet"
) -> Tuple[pd.DataFrame, str]:
    """
    Load scan results from local file or S3.
    
    Args:
        input_path: Local path to parquet file (optional)
        s3_bucket: S3 bucket name (optional)
        s3_key: Specific S3 key to download (optional)
        s3_input_prefix: S3 prefix to find latest scan (optional)
        local_download_path: Where to save S3 downloads
    
    Returns:
        Tuple of (DataFrame, repo_name)
    """
    repo_name = None
    
    # Case 1: Local file provided
    if input_path and os.path.exists(input_path):
        print(f"Loading scan results from local file: {input_path}")
        df = pd.read_parquet(input_path)
        # Try to extract repo name from path
        repo_name = os.path.basename(os.path.dirname(input_path))
        return df, repo_name
    
    # Case 2: S3 with specific key
    if s3_bucket and s3_key:
        print(f"Loading scan results from S3: s3://{s3_bucket}/{s3_key}")
        if _download_from_s3(s3_bucket, s3_key, local_download_path):
            df = pd.read_parquet(local_download_path)
            # Extract repo name from S3 key
            parts = s3_key.split('/')
            repo_name = parts[1] if len(parts) > 1 else None
            return df, repo_name
        else:
            raise RuntimeError(f"Failed to download from S3: s3://{s3_bucket}/{s3_key}")
    
    # Case 3: S3 with prefix (find latest)
    if s3_bucket and s3_input_prefix:
        print(f"Finding latest scan in s3://{s3_bucket}/{s3_input_prefix}/")
        folder_name, s3_key = _find_latest_scan_in_s3(s3_bucket, s3_input_prefix)
        
        if not s3_key:
            raise RuntimeError(f"No scan results found in s3://{s3_bucket}/{s3_input_prefix}/")
        
        if _download_from_s3(s3_bucket, s3_key, local_download_path):
            df = pd.read_parquet(local_download_path)
            repo_name = folder_name
            return df, repo_name
        else:
            raise RuntimeError(f"Failed to download latest scan from S3")
    
    raise ValueError("Must provide either input_path or S3 parameters (s3_bucket + s3_key or s3_input_prefix)")


def vuln_code_identify(
        vuln_scan_df: pd.DataFrame, 
        dep_repos_root_dir_path: str,
        output_scans_dir_path: str | None, 
        output_scans_pd_dir_path: str, 
        output_pd_path: str,
        semgrep_jobs: int = 10,
        enable_dataflow_traces: bool = True,
        semgrep_timeout: int = None,
        max_file_size: int = None,
        s3_bucket: str | None = None,
        s3_output_prefix: str | None = None,
        repo_name: str | None = None) -> pd.DataFrame:
    """
    Run vulnerability code identification for unfixed vulnerabilities.

    Args:
        vuln_scan_df: DataFrame with vulnerability scan results
        dep_repos_root_dir_path: Root directory for cloning repos
        output_scans_dir_path: Directory for raw semgrep JSON outputs
        output_scans_pd_dir_path: Directory for processed parquet outputs
        output_pd_path: Path for final output parquet file
        semgrep_jobs: Number of parallel semgrep jobs (default: 10)
        enable_dataflow_traces: Enable dataflow traces (default: True)
        semgrep_timeout: Timeout per rule in seconds (default: None)
        max_file_size: Max file size to scan in bytes (default: None)
        s3_bucket: S3 bucket name for uploading results (optional)
        s3_output_prefix: S3 prefix for outputs (optional)
        repo_name: Repository name for S3 folder structure (optional)

    Returns:
        pd.DataFrame: DataFrame containing vulnerability code identification results.
    """
    # Determine if S3 upload is enabled
    upload_to_s3 = bool(s3_bucket and s3_output_prefix and repo_name)
    
    if upload_to_s3:
        print(f"S3 upload enabled: s3://{s3_bucket}/{s3_output_prefix}/{repo_name}/")
    
    # skip if output_pd_path already exists and is non-empty
    if os.path.isfile(output_pd_path) and os.path.getsize(output_pd_path) > 0:
        print(f"Vulnerability code identification dataframe file {output_pd_path} already exists and is non-empty. Skipping vulnerability code identification.")
        
        # Upload existing file to S3 if enabled
        if upload_to_s3:
            s3_key = f"{s3_output_prefix}/{repo_name}/vuln_code_identification.parquet"
            _upload_to_s3(output_pd_path, s3_bucket, s3_key)
        
        return pd.read_parquet(output_pd_path)
    
    # identify unfixed vulnerabilities
    unfixed_vuln_df = vuln_scan_df[vuln_scan_df["fixed_version"].isnull()]
    # identify fixed vulnerabilities
    fixed_vuln_df = vuln_scan_df[vuln_scan_df["fixed_version"].notnull()]

    # initialize output_df to None
    output_df = None
    skipped_unfixed_vulns = []

    # iterate through unfixed vulnerabilities and run code identification
    for _, row in unfixed_vuln_df.iterrows():
        # skip if source_code_location is empty but track the skipped rows so that they can be appended to output_df later
        if not row["source_code_location"]:
            skipped_unfixed_vulns.append(row)
            print(f"Skipping vulnerability cve_id={row['cve_id']}, package_name={row['package_name']}, package_version={row['package_version']} as source_code_location is empty.")
            continue
        
        repo_url = row["source_code_location"] + ".git" # source_code_location is github url without .git
        # extract repo name from github url
        current_repo_name = repo_url.split("/")[-1].replace(".git", "")
        # derive dir path to clone forked repo into
        dir_path = os.path.join(dep_repos_root_dir_path, current_repo_name)

        # ensure Vuln-Guard organization personal access token is provided in env vars so that gh CLI can be invoked successfully
        if not GH_TOKEN:
            raise ValueError("GH_TOKEN environment variable not set. Cannot authenticate with GitHub CLI. Please set GH_TOKEN to a valid GitHub personal access token with appropriate permissions.")

        # fork repo to Vuln-Guard organization if not already forked
        is_forked = None
        try:
            repo_info = run_cmd_and_parse_output(["gh", "repo", "view", f"{GITHUB_ORG_NAME}/{current_repo_name}", '--json', 'isFork'])
            is_forked = repo_info.get("isFork", False)
        except Exception:
            is_forked = False
        if not is_forked:
            run_cmd(["gh", "repo", "fork", repo_url, "--org", GITHUB_ORG_NAME, "--clone=false"])
            print(f"Forked repo {repo_url} to organization {GITHUB_ORG_NAME}")
        else:
            print(f"Repo {current_repo_name} already forked to organization {GITHUB_ORG_NAME}. Skipping forking.")

        # clone forked repo into dir_path if not already cloned
        forked_repo_url = f"https://github.com/{GITHUB_ORG_NAME}/{current_repo_name}.git"
        if repo_url and dir_path and (not os.path.exists(dir_path) or not os.listdir(dir_path)):
            run_cmd(["git", "clone", forked_repo_url, dir_path])
            print(f"Cloned repo {forked_repo_url} into {dir_path}")
        else:
            print(f"Repo {forked_repo_url} already cloned in {dir_path}. Skipping cloning.")

        # in order to get semgrep to work we need to tell git to trust the absolute dir_path because under the hood, semgrep runs `git -C <abs_dir_path> ls-files -z --cached`.
        abs_dir_path = os.path.abspath(dir_path)
        run_cmd(["git", "config", "--global", "--add", "safe.directory", abs_dir_path])

        # run semgrep scan on the cloned forked repo if corresponding pandas dataframe doesn't already exist
        output_scan_path = os.path.join(output_scans_dir_path, f"{current_repo_name}_semgrep_scan.json") if output_scans_dir_path else None
        if output_scan_path and os.path.isfile(output_scan_path) and os.path.getsize(output_scan_path) > 0:
            print(f"Semgrep scan output file {output_scan_path} already exists and is non-empty. Skipping semgrep scan.")
            with open(output_scan_path, "r") as f:
                semgrep_scan_result = json.load(f)
        else:
            # note: provide semgrep app token in env vars to get fuller results
            semgrep_scan_result = _run_semgrep_scan(
                dir_path, 
                output_path=output_scan_path,
                num_subprocesses=semgrep_jobs,
                enable_dataflow_traces=enable_dataflow_traces,
                timeout=semgrep_timeout,
                max_file_size=max_file_size
            )
            
            # Upload raw semgrep scan to S3 if enabled
            if upload_to_s3 and output_scan_path and os.path.isfile(output_scan_path):
                s3_key = f"{s3_output_prefix}/{repo_name}/scans_raw/{current_repo_name}_semgrep_scan.json"
                _upload_to_s3(output_scan_path, s3_bucket, s3_key)
        
        print("finished semgrep scan.")

        # convert semgrep scan result to pandas dataframe if corresponding pandas dataframe doesn't already exist
        output_scan_pd_path = os.path.join(output_scans_pd_dir_path, f"{current_repo_name}_semgrep_scan_pd.parquet") if output_scans_pd_dir_path else None
        if output_scan_pd_path and os.path.isfile(output_scan_pd_path) and os.path.getsize(output_scan_pd_path) > 0:
            print(f"Semgrep scan pandas dataframe file {output_scan_pd_path} already exists and is non-empty. Skipping converting semgrep scan to pandas dataframe.")
            result_df = pd.read_parquet(output_scan_pd_path)
        else:
            result_df = _extract_semgrep_df(semgrep_scan_result, output_path=output_scan_pd_path)
            
            # Upload processed parquet to S3 if enabled
            if upload_to_s3 and output_scan_pd_path and os.path.isfile(output_scan_pd_path):
                s3_key = f"{s3_output_prefix}/{repo_name}/scans_pd/{current_repo_name}_semgrep_scan_pd.parquet"
                _upload_to_s3(output_scan_pd_path, s3_bucket, s3_key)
        
        print("finished converting semgrep scan to pandas dataframe")

        # combine semgrep scan result dataframe with vuln_scan_df on matching cwe_id and filename in summary, description, or references
        cwe_id = row["cwe_id"]
        result_df = result_df[result_df.apply(lambda r: (r['cwe_id'] ==  cwe_id) & any(r['filename'] in str(row[col]) for col in ['summary', 'description', 'references']), axis=1)]
        if not result_df.empty:
            print(f"matching rows found in semgrep scan for vulnerability cve_id={row['cve_id']}: \n {result_df}")
        merged_df = pd.merge(row.to_frame().T, result_df, how='left', on='cwe_id')

        # append merged_df to output_df
        output_df = append_df(output_df, merged_df)

    # append skipped_unfixed_vulns to output_df with NaN values for semgrep columns
    if skipped_unfixed_vulns:
        skipped_unfixed_vulns_df = pd.DataFrame(skipped_unfixed_vulns)
        output_df = append_df(output_df, skipped_unfixed_vulns_df)
    # append fixed_vuln_df to output_df with NaN values for semgrep columns
    if not fixed_vuln_df.empty:
        output_df = append_df(output_df, fixed_vuln_df)
    
    # save output DataFrame to parquet
    save_df(output_df, output_pd_path)
    print(f"Saved final vulnerability code identification results to {output_pd_path}")
    
    # Upload final output to S3 if enabled
    if upload_to_s3 and os.path.isfile(output_pd_path):
        s3_key = f"{s3_output_prefix}/{repo_name}/vuln_code_identification.parquet"
        _upload_to_s3(output_pd_path, s3_bucket, s3_key)

    return output_df


def _run_semgrep_scan(
        dir_path: str, 
        output_path: str | None, 
        num_subprocesses: int = 10,
        enable_dataflow_traces: bool = True,
        timeout: int = None,
        max_file_size: int = None) -> Dict[str, Any]:
    """
    Run semgrep scan on the given directory.

    Args:
        dir_path (str): Path to the directory to scan.
        output_path (str | None): Path to save the semgrep scan output JSON file. If None, output is not saved to file.
        num_subprocesses (int): Number of parallel jobs (default: 10)
        enable_dataflow_traces (bool): Enable dataflow traces (default: True)
        timeout (int): Timeout per rule in seconds (default: None)
        max_file_size (int): Max file size to scan in bytes (default: None)

    Returns:
        Dict[str, Any]: Semgrep scan result as a dictionary.
    """
    semgrep_cmd = [
        "semgrep",
        "scan",
        dir_path,
        "-j",
        str(num_subprocesses),
        "--json"
    ]
    
    # Add optional parameters
    if enable_dataflow_traces:
        semgrep_cmd.append("--dataflow-traces")
    
    if timeout:
        semgrep_cmd.extend(["--timeout", str(timeout)])
    
    if max_file_size:
        semgrep_cmd.extend(["--max-target-bytes", str(max_file_size)])
    
    if output_path:
        semgrep_cmd.extend(["--json-output", output_path])

    return run_cmd_and_parse_output(semgrep_cmd)


def _extract_semgrep_df(semgrep_result: Dict[str, Any], output_path: str) -> pd.DataFrame:
    """
    Extract relevant information from semgrep scan result and convert to pandas DataFrame.

    Args:
        semgrep_result (Dict[str, Any]): Semgrep scan result as a dictionary.
        output_path (str): Path to save the extracted DataFrame

    Returns:
        pd.DataFrame: DataFrame containing relevant semgrep scan information.
    """
    semgrep_df = pd.json_normalize(semgrep_result["results"])
    # if extra.dataflow_trace fields are missing, add them with NaN values
    for col in ['extra.dataflow_trace.taint_source', 'extra.dataflow_trace.intermediate_vars', 'extra.dataflow_trace.taint_sink']:
        if col not in semgrep_df.columns:
            semgrep_df[col] = np.nan
    # extract relevant columns (only those that exist in the DataFrame)
    relevant_columns = ['path', 'start.line', 'start.col', 'start.offset', 'end.line', 'end.col', 'end.offset', 'extra.message', 'extra.metadata.cwe', "extra.metadata.likelihood", "extra.metadata.impact", "extra.metadata.confidence", "extra.metadata.vulnerability_class", "extra.severity", "extra.lines", "extra.validation_state", "extra.fix", "extra.dataflow_trace.taint_source", "extra.dataflow_trace.intermediate_vars", "extra.dataflow_trace.taint_sink"]
    # filter to only columns that exist
    existing_columns = [col for col in relevant_columns if col in semgrep_df.columns]
    semgrep_extracted_df = semgrep_df[existing_columns] 
    semgrep_extracted_df = semgrep_extracted_df.explode(['extra.metadata.cwe'])
    semgrep_extracted_df[['cwe_id', 'cwe_name']] = semgrep_extracted_df['extra.metadata.cwe'].str.split(': ', expand=True)
    semgrep_extracted_df.drop(columns=['cwe_name','extra.metadata.cwe'], inplace=True)
    semgrep_extracted_df = semgrep_extracted_df.explode(['extra.metadata.vulnerability_class'])
    semgrep_extracted_df['filename'] = semgrep_extracted_df['path'].apply(lambda x: x.split('/')[-1].split('.')[0])
    # convert taint_source, intermediate_vars, taint_sink lists to strings
    semgrep_extracted_df['extra_dataflow_trace_taint_source'] = semgrep_extracted_df['extra.dataflow_trace.taint_source'].astype(str)
    semgrep_extracted_df['extra_dataflow_trace_intermediate_vars'] = semgrep_extracted_df['extra.dataflow_trace.intermediate_vars'].astype(str)
    semgrep_extracted_df['extra_dataflow_trace_taint_sink'] = semgrep_extracted_df['extra.dataflow_trace.taint_sink'].astype(str)
    semgrep_extracted_df.drop(columns=['extra.dataflow_trace.taint_source', 'extra.dataflow_trace.intermediate_vars', 'extra.dataflow_trace.taint_sink'], inplace=True)
    # rename columns with dots removed
    semgrep_extracted_df.columns = semgrep_extracted_df.columns.str.replace('.', '_')

    # save to parquet if output_path is provided
    if output_path:
        save_df(semgrep_extracted_df, output_path)
        print(f"Saved semgrep extracted DataFrame to {output_path}")

    return semgrep_extracted_df


def main():
    """Main entry point for CLI usage."""
    parser = argparse.ArgumentParser(
        description="Vulnerability Code Identification Workflow - Standalone"
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--input-file",
        type=str,
        help="Local path to scan results parquet file"
    )
    input_group.add_argument(
        "--s3-input-key",
        type=str,
        help="Specific S3 key to download (requires --s3-bucket)"
    )
    input_group.add_argument(
        "--s3-input-prefix",
        type=str,
        help="S3 prefix to find latest scan (requires --s3-bucket)"
    )
    
    # S3 configuration
    parser.add_argument(
        "--s3-bucket",
        type=str,
        default=os.getenv("S3_BUCKET"),
        help="S3 bucket name (or set S3_BUCKET env var)"
    )
    parser.add_argument(
        "--s3-output-prefix",
        type=str,
        default=os.getenv("S3_OUTPUT_PREFIX", "identifications"),
        help="S3 prefix for output files"
    )
    
    # Processing options
    parser.add_argument(
        "--repos-dir",
        type=str,
        default="/tmp/repos",
        help="Directory to clone repositories"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="/tmp/identifications",
        help="Directory for output files"
    )
    parser.add_argument(
        "--semgrep-jobs",
        type=int,
        default=int(os.getenv("SEMGREP_NUM_JOBS", "16")),
        help="Number of Semgrep parallel jobs"
    )
    parser.add_argument(
        "--semgrep-timeout",
        type=int,
        default=int(os.getenv("SEMGREP_TIMEOUT", "600")),
        help="Semgrep timeout per rule in seconds"
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=int(os.getenv("SEMGREP_MAX_FILE_SIZE", "1000000")),
        help="Maximum file size to scan in bytes"
    )
    parser.add_argument(
        "--enable-dataflow-traces",
        action="store_true",
        default=os.getenv("ENABLE_DATAFLOW_TRACES", "false").lower() == "true",
        help="Enable Semgrep dataflow traces"
    )
    
    args = parser.parse_args()
    
    print("="*80)
    print("VULNERABILITY CODE IDENTIFICATION WORKFLOW")
    print("="*80)
    
    # Load scan results
    print("\n📥 Loading scan results...")
    scan_df, repo_name = load_scan_results(
        input_path=args.input_file,
        s3_bucket=args.s3_bucket,
        s3_key=args.s3_input_key,
        s3_input_prefix=args.s3_input_prefix
    )
    
    print(f"✓ Loaded {len(scan_df)} vulnerability records")
    if repo_name:
        print(f"✓ Repository: {repo_name}")
    
    # Create output directories
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_folder = f"{repo_name}-{timestamp}" if repo_name else f"scan-{timestamp}"
    
    output_base = os.path.join(args.output_dir, output_folder)
    output_scans_raw = os.path.join(output_base, "scans_raw")
    output_scans_pd = os.path.join(output_base, "scans_pd")
    
    os.makedirs(output_scans_raw, exist_ok=True)
    os.makedirs(output_scans_pd, exist_ok=True)
    os.makedirs(args.repos_dir, exist_ok=True)
    
    output_file = os.path.join(output_base, "vuln_code_identification.parquet")
    
    print(f"\n📁 Output directory: {output_base}")
    
    # Run vulnerability code identification
    print("\n🔍 Running vulnerability code identification...")
    result_df = vuln_code_identify(
        vuln_scan_df=scan_df,
        dep_repos_root_dir_path=args.repos_dir,
        output_scans_dir_path=output_scans_raw,
        output_scans_pd_dir_path=output_scans_pd,
        output_pd_path=output_file,
        semgrep_jobs=args.semgrep_jobs,
        enable_dataflow_traces=args.enable_dataflow_traces,
        semgrep_timeout=args.semgrep_timeout,
        max_file_size=args.max_file_size,
        s3_bucket=args.s3_bucket if args.s3_output_prefix else None,
        s3_output_prefix=args.s3_output_prefix,
        repo_name=repo_name
    )
    
    print("\n" + "="*80)
    print("✅ WORKFLOW COMPLETE")
    print("="*80)
    print(f"Total vulnerabilities processed: {len(result_df)}")
    print(f"Local output: {output_file}")
    
    if args.s3_bucket and args.s3_output_prefix:
        s3_uri = f"s3://{args.s3_bucket}/{args.s3_output_prefix}/{repo_name}/"
        print(f"S3 output: {s3_uri}")
    
    print("="*80)


if __name__ == "__main__":
    main()