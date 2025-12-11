"""
Run vulnerability code identification for unfixed vulnerabilities.

IMPROVEMENTS:
- Multi-strategy matching (CWE, component, vulnerability class)
- Better field preservation
- Clearer logging
"""

from __future__ import annotations
from typing import Dict, Any
import pandas as pd
import os
import json
from src.backend.utils.cmd import run_cmd, run_cmd_and_parse_output
from src.backend.utils.df import append_df, save_df
from dotenv import load_dotenv
import numpy as np

load_dotenv()

GH_TOKEN = os.environ.get("GH_TOKEN", "")
SEMGREP_APP_TOKEN = os.environ.get("SEMGREP_APP_TOKEN", "")
GITHUB_ORG_NAME = "Vuln-Guard"

def vuln_code_identify(
        vuln_scan_df: pd.DataFrame, 
        dep_repos_root_dir_path: str,
        output_scans_dir_path: str | None, 
        output_scans_pd_dir_path: str, 
        output_pd_path: str,
        matching_strategy: str = "flexible",
        scan_all_vulnerabilities: bool = False) -> pd.DataFrame:
    """
    Run vulnerability code identification for unfixed vulnerabilities.
    
    Args:
        matching_strategy: "strict", "flexible", or "loose" matching
        scan_all_vulnerabilities: If True, scan ALL vulns (including fixed)

    Returns:
        pd.DataFrame: DataFrame containing vulnerability code identification results.
    """
    # skip if output_pd_path already exists and is non-empty
    if os.path.isfile(output_pd_path) and os.path.getsize(output_pd_path) > 0:
        print(f"Vulnerability code identification dataframe file {output_pd_path} already exists and is non-empty. Skipping vulnerability code identification.")
        return pd.read_parquet(output_pd_path)
    
    # Determine which vulnerabilities to scan
    if scan_all_vulnerabilities:
        # Scan ALL vulnerabilities (both fixed and unfixed)
        unfixed_vuln_df = vuln_scan_df  # Process all
        fixed_vuln_df = pd.DataFrame()  # None to skip at end
        print(f"ℹ️  scan_all_vulnerabilities=True: Will scan all {len(vuln_scan_df)} vulnerabilities")
    else:
        # Original behavior: only scan unfixed
        unfixed_vuln_df = vuln_scan_df[vuln_scan_df["fixed_version"].isnull()]
        fixed_vuln_df = vuln_scan_df[vuln_scan_df["fixed_version"].notnull()]

    print(f"\n{'='*80}")
    print(f"VULNERABILITY CODE IDENTIFICATION")
    print(f"{'='*80}")
    print(f"Total vulnerabilities: {len(vuln_scan_df)}")
    print(f"  - Unfixed: {len(unfixed_vuln_df)} (will run Semgrep)")
    print(f"  - Fixed: {len(fixed_vuln_df)} (will skip)")

    # initialize output_df to None
    output_df = None
    skipped_unfixed_vulns = []
    match_stats = {'cwe': 0, 'component': 0, 'vuln_class': 0, 'no_match': 0}

    # iterate through unfixed vulnerabilities and run code identification
    for idx, row in unfixed_vuln_df.iterrows():
        print(f"\n{'-'*80}")
        print(f"Processing [{idx+1}/{len(unfixed_vuln_df)}]: {row['cve_id']} - {row['package_name']} {row['package_version']}")
        
        # skip if source_code_location is empty but track the skipped rows so that they can be appended to output_df later
        if not row["source_code_location"]:
            skipped_unfixed_vulns.append(row)
            print(f"  ⚠️  Skipping: No source_code_location")
            continue
        
        repo_url = row["source_code_location"] + ".git" # source_code_location is github url without .git
        # extract repo name from github url
        repo_name = repo_url.split("/")[-1].replace(".git", "")
        # derive dir path to clone forked repo into
        dir_path = os.path.join(dep_repos_root_dir_path, repo_name)

        # ensure Vuln-Guard organization personal access token is provided in env vars so that gh CLI can be invoked successfully
        if not GH_TOKEN:
            raise ValueError("GH_TOKEN environment variable not set. Cannot authenticate with GitHub CLI. Please set GH_TOKEN to a valid GitHub personal access token with appropriate permissions.")

        # fork repo to Vuln-Guard organization if not already forked
        is_forked = None
        try:
            repo_info = run_cmd_and_parse_output(["gh", "repo", "view", f"{GITHUB_ORG_NAME}/{repo_name}", '--json', 'isFork'])
            is_forked = repo_info.get("isFork", False)
        except Exception:
            is_forked = False
        if not is_forked:
            run_cmd(["gh", "repo", "fork", repo_url, "--org", GITHUB_ORG_NAME, "--clone=false"])
            print(f"  📦 Forked repo to {GITHUB_ORG_NAME}/{repo_name}")
        else:
            print(f"  ✓ Repo already forked")

        # clone forked repo into dir_path if not already cloned
        forked_repo_url = f"https://github.com/{GITHUB_ORG_NAME}/{repo_name}.git"
        if repo_url and dir_path and (not os.path.exists(dir_path) or not os.listdir(dir_path)):
            run_cmd(["git", "clone", forked_repo_url, dir_path])
            print(f"  📥 Cloned to {dir_path}")
        else:
            print(f"  ✓ Repo already cloned")

        # in order to get semgrep to work we need to tell git to trust the absolute dir_path because under the hood, semgrep runs `git -C <abs_dir_path> ls-files -z --cached`.
        abs_dir_path = os.path.abspath(dir_path)
        run_cmd(["git", "config", "--global", "--add", "safe.directory", abs_dir_path])

        # run semgrep scan on the cloned forked repo if corresponding pandas dataframe doesn't already exist
        output_scan_path = os.path.join(output_scans_dir_path, f"{repo_name}_semgrep_scan.json") if output_scans_dir_path else None
        if output_scan_path and os.path.isfile(output_scan_path) and os.path.getsize(output_scan_path) > 0:
            print(f"  ✓ Using cached Semgrep scan")
            with open(output_scan_path, "r") as f:
                semgrep_scan_result = json.load(f)
        else:
            print(f"  🔍 Running Semgrep scan...")
            # note: provide semgrep app token in env vars to get fuller results
            semgrep_scan_result = _run_semgrep_scan(dir_path, output_path=output_scan_path)
            print(f"  ✓ Semgrep scan complete")

        # convert semgrep scan result to pandas dataframe if corresponding pandas dataframe doesn't already exist
        output_scan_pd_path = os.path.join(output_scans_pd_dir_path, f"{repo_name}_semgrep_scan_pd.parquet") if output_scans_pd_dir_path else None
        if output_scan_pd_path and os.path.isfile(output_scan_pd_path) and os.path.getsize(output_scan_pd_path) > 0:
            print(f"  ✓ Using cached Semgrep DataFrame")
            result_df = pd.read_parquet(output_scan_pd_path)
        else:
            result_df = _extract_semgrep_df(semgrep_scan_result, output_path=output_scan_pd_path)
            print(f"  ✓ Converted to DataFrame: {len(result_df)} findings")

        # Multi-strategy matching to link Semgrep findings to Grype vulnerabilities
        print(f"  🔗 Attempting to match Semgrep findings...")
        matched_df, strategy = _match_semgrep_to_grype(result_df, row)
        
        if not matched_df.empty:
            print(f"  ✅ Matched {len(matched_df)} finding(s) using '{strategy}' strategy")
            match_stats[strategy] += 1
        else:
            print(f"  ⚠️  No matches found")
            match_stats['no_match'] += 1
        
        # Merge the matched results with the original row
        # FIX: Don't merge on='cwe_id' because Grype and Semgrep may have different CWEs
        # Instead, create one output row for each matched Semgrep finding
        if not matched_df.empty:
            # Option 1: Expand rows - one output row per Semgrep finding
            output_rows = []
            for _, semgrep_row in matched_df.iterrows():
                # Start with the Grype CVE data
                combined_row = row.to_dict()
                # Add all Semgrep fields (overwrite if they exist)
                combined_row.update(semgrep_row.to_dict())
                output_rows.append(combined_row)
            merged_df = pd.DataFrame(output_rows)
        else:
            # No matches - just keep the Grype row as-is
            merged_df = row.to_frame().T

        # append merged_df to output_df
        output_df = append_df(output_df, merged_df)

    # Print matching statistics
    print(f"\n{'='*80}")
    print(f"MATCHING STATISTICS")
    print(f"{'='*80}")
    total_processed = sum(match_stats.values())
    for strategy, count in match_stats.items():
        pct = (count / total_processed * 100) if total_processed > 0 else 0
        print(f"  {strategy.upper():15s}: {count:3d} ({pct:5.1f}%)")
    print(f"{'='*80}\n")

    # append skipped_unfixed_vulns to output_df with NaN values for semgrep columns
    if skipped_unfixed_vulns:
        skipped_unfixed_vulns_df = pd.DataFrame(skipped_unfixed_vulns)
        output_df = append_df(output_df, skipped_unfixed_vulns_df)
    # append fixed_vuln_df to output_df with NaN values for semgrep columns
    if not fixed_vuln_df.empty:
        output_df = append_df(output_df, fixed_vuln_df)
    # save output DataFrame to parquet
    save_df(output_df, output_pd_path)

    return output_df


def _match_semgrep_to_grype(semgrep_df: pd.DataFrame, grype_row: pd.Series) -> tuple[pd.DataFrame, str]:
    """
    Multi-strategy matching to link Semgrep findings to Grype vulnerabilities.
    
    Strategies (in order of precedence):
    1. CWE ID match
    2. Component/package name match
    3. Vulnerability class match
    
    Returns:
        Tuple of (matched DataFrame, strategy name)
    """
    if semgrep_df.empty:
        return pd.DataFrame(), 'no_match'
    
    cwe_id = grype_row.get("cwe_id")
    package_name = grype_row.get("package_name", "")
    
    # Strategy 1: CWE ID match (most accurate)
    if cwe_id and pd.notna(cwe_id):
        matched = semgrep_df[semgrep_df['cwe_id'] == cwe_id]
        if not matched.empty:
            return matched, 'cwe'
    
    # Strategy 2: Component/package name match
    # Check if package name appears in any of the Semgrep paths or messages
    if package_name:
        matched = semgrep_df[
            semgrep_df.apply(
                lambda r: (
                    package_name.lower() in str(r.get('path', '')).lower() or
                    package_name.lower() in str(r.get('extra_message', '')).lower() or
                    package_name.lower() in str(r.get('filename', '')).lower()
                ),
                axis=1
            )
        ]
        if not matched.empty:
            return matched, 'component'
    
    # Strategy 3: Vulnerability class match
    # If Grype has vulnerability class info in description, try to match
    vuln_classes = ['injection', 'xss', 'csrf', 'deserialization', 'xxe', 'ssrf']
    grype_desc = str(grype_row.get('description', '')).lower() + " " + str(grype_row.get('summary', '')).lower()
    
    for vuln_class in vuln_classes:
        if vuln_class in grype_desc:
            matched = semgrep_df[
                semgrep_df.apply(
                    lambda r: vuln_class in str(r.get('extra_metadata_vulnerability_class', '')).lower(),
                    axis=1
                )
            ]
            if not matched.empty:
                return matched, 'vuln_class'
    
    return pd.DataFrame(), 'no_match'


def _run_semgrep_scan(dir_path: str, output_path: str | None, num_subprocesses=10) -> Dict[str, Any]:
    """
    Run semgrep scan on the given directory.

    Args:
        dir_path (str): Path to the directory to scan.
        output_path (str | None): Path to save the semgrep scan output JSON file. If None, output is not saved to file.

    Returns:
        Dict[str, Any]: Semgrep scan result as a dictionary.
    """
    semgrep_cmd = [
        "semgrep",
        "scan",
        dir_path,
        "-j",
        str(num_subprocesses),
        "--json",
        "--dataflow-traces"
    ]
    if output_path:
        semgrep_cmd.extend(["--json-output", output_path])

    return run_cmd_and_parse_output(semgrep_cmd)

def _extract_semgrep_df(semgrep_result: Dict[str, Any], output_path: str) -> pd.DataFrame:
    """
    Extract relevant information from semgrep scan result and convert to pandas DataFrame.

    Args:
        semgrep_result (Dict[str, Any]): Semgrep scan result as a dictionary.

    Returns:
        pd.DataFrame: DataFrame containing relevant semgrep scan information.
    """
    if not semgrep_result.get("results"):
        print("  ⚠️  Semgrep returned no results")
        return pd.DataFrame()
    
    semgrep_df = pd.json_normalize(semgrep_result["results"])
    
    # if extra.dataflow_trace fields are missing, add them with NaN values
    for col in ['extra.dataflow_trace.taint_source', 'extra.dataflow_trace.intermediate_vars', 'extra.dataflow_trace.taint_sink']:
        if col not in semgrep_df.columns:
            semgrep_df[col] = np.nan
    
    # extract relevant columns
    relevant_columns = [
        'path', 
        'start.line', 'start.col', 'start.offset', 
        'end.line', 'end.col', 'end.offset', 
        'extra.message', 
        'extra.metadata.cwe', 
        "extra.metadata.likelihood", 
        "extra.metadata.impact", 
        "extra.metadata.confidence", 
        "extra.metadata.vulnerability_class", 
        "extra.severity", 
        "extra.lines", 
        "extra.validation_state", 
        "extra.fix", 
        "extra.dataflow_trace.taint_source", 
        "extra.dataflow_trace.intermediate_vars", 
        "extra.dataflow_trace.taint_sink"
    ]
    
    # Only select columns that exist
    available_columns = [col for col in relevant_columns if col in semgrep_df.columns]
    semgrep_extracted_df = semgrep_df[available_columns].copy()
    
    # Handle CWE extraction
    if 'extra.metadata.cwe' in semgrep_extracted_df.columns:
        semgrep_extracted_df = semgrep_extracted_df.explode(['extra.metadata.cwe'])
        semgrep_extracted_df[['cwe_id', 'cwe_name']] = semgrep_extracted_df['extra.metadata.cwe'].str.split(': ', expand=True)
        semgrep_extracted_df.drop(columns=['cwe_name','extra.metadata.cwe'], inplace=True)
    else:
        semgrep_extracted_df['cwe_id'] = None
    
    # Handle vulnerability class
    if 'extra.metadata.vulnerability_class' in semgrep_extracted_df.columns:
        semgrep_extracted_df = semgrep_extracted_df.explode(['extra.metadata.vulnerability_class'])
    
    # Extract filename from path
    if 'path' in semgrep_extracted_df.columns:
        semgrep_extracted_df['filename'] = semgrep_extracted_df['path'].apply(lambda x: x.split('/')[-1].split('.')[0] if pd.notna(x) else None)
    
    # convert taint_source, intermediate_vars, taint_sink lists to strings
    for col in ['extra.dataflow_trace.taint_source', 'extra.dataflow_trace.intermediate_vars', 'extra.dataflow_trace.taint_sink']:
        if col in semgrep_extracted_df.columns:
            new_col = col.replace('.', '_')
            semgrep_extracted_df[new_col] = semgrep_extracted_df[col].astype(str)
            semgrep_extracted_df.drop(columns=[col], inplace=True)
    
    # rename columns with dots removed
    semgrep_extracted_df.columns = semgrep_extracted_df.columns.str.replace('.', '_')

    # save to parquet if output_path is provided
    if output_path:
        save_df(semgrep_extracted_df, output_path)
        print(f"  💾 Saved Semgrep DataFrame to {output_path}")

    return semgrep_extracted_df


def scan_repository(
    repo_path: str,
    output_dir: str,
    repo_name: str = None,
    semgrep_jobs: int = 10,
    enable_dataflow_traces: bool = True,
    semgrep_timeout: int = 600,
    max_file_size: int = 1000000,
    semgrep_config: str = "auto",
    s3_bucket: str = None,
    s3_output_prefix: str = None
) -> pd.DataFrame:
    """
    Scan any repository directly with Semgrep and extract all vulnerability findings.
    
    This is the direct scan mode that can scan any arbitrary repository
    without requiring pre-existing CVE data.
    
    Args:
        repo_path: Path to the repository to scan (local path)
        output_dir: Directory for output files
        repo_name: Name for the repository (auto-detected if not provided)
        semgrep_jobs: Number of parallel Semgrep jobs (default: 10)
        enable_dataflow_traces: Enable dataflow traces (default: True)
        semgrep_timeout: Timeout per rule in seconds (default: 600)
        max_file_size: Maximum file size to scan in bytes (default: 1000000)
        semgrep_config: Semgrep config to use (default: "auto")
        s3_bucket: S3 bucket for uploading results (optional - not implemented)
        s3_output_prefix: S3 prefix for outputs (optional - not implemented)
    
    Returns:
        DataFrame containing all Semgrep findings with extracted fields
    """
    from pathlib import Path
    
    print(f"\n{'='*80}")
    print(f"REPOSITORY CODE SCAN (Direct Mode)")
    print(f"{'='*80}")
    print(f"Repository: {repo_path}")
    print(f"Output directory: {output_dir}")
    print(f"Semgrep jobs: {semgrep_jobs}")
    print(f"Dataflow traces: {enable_dataflow_traces}")
    
    # Auto-detect repo name if not provided
    if repo_name is None:
        repo_name = Path(repo_path).name
        print(f"Auto-detected repo name: {repo_name}")
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Define output paths
    output_scan_path = os.path.join(output_dir, f"{repo_name}_semgrep_scan.json")
    output_pd_path = os.path.join(output_dir, f"{repo_name}_semgrep_scan.parquet")
    
    # Check if already scanned
    if os.path.isfile(output_pd_path) and os.path.getsize(output_pd_path) > 0:
        print(f"✓ Using cached scan: {output_pd_path}")
        result_df = pd.read_parquet(output_pd_path)
        print(f"✓ Loaded {len(result_df)} cached findings")
    else:
        # Run Semgrep scan
        print(f"🔍 Running Semgrep scan...")
        
        # Build semgrep command with custom options
        semgrep_cmd = [
            "semgrep",
            "scan",
            repo_path,
            "-j", str(semgrep_jobs),
            "--json",
            "--timeout", str(semgrep_timeout),
            "--max-target-bytes", str(max_file_size)
        ]
        
        if enable_dataflow_traces:
            semgrep_cmd.append("--dataflow-traces")
        
        if semgrep_config != "auto":
            semgrep_cmd.extend(["--config", semgrep_config])
        
        semgrep_cmd.extend(["--json-output", output_scan_path])
        
        try:
            semgrep_result = run_cmd_and_parse_output(semgrep_cmd)
            print(f"✓ Semgrep scan complete")
            
            # Convert to DataFrame
            result_df = _extract_semgrep_df(semgrep_result, output_path=output_pd_path)
            print(f"✓ Found {len(result_df)} code vulnerabilities")
            
        except Exception as e:
            print(f"❌ Semgrep scan failed: {e}")
            # Return empty DataFrame on failure
            result_df = pd.DataFrame()
            save_df(result_df, output_pd_path)
    
    # Upload to S3 if requested (placeholder)
    if s3_bucket:
        print(f"⚠️  S3 upload requested but not implemented yet")
        print(f"   Would upload to: s3://{s3_bucket}/{s3_output_prefix or ''}")
    
    return result_df