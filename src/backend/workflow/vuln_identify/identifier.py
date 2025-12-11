"""
Vulnerability Code Identification Entry Point

This module provides the main entry point for vulnerability code identification,
supporting two modes:
1. Direct repository scanning - scan any repo with Semgrep
2. CVE-correlated scanning - correlate known CVEs with Semgrep findings

Usage:
    # Direct scan mode
    from identifier import scan_repository
    findings = scan_repository("/path/to/repo", "/output/dir")

    # CVE-correlated mode  
    from identifier import identify_vulns
    results = identify_vulns(vuln_scan_results, ...)
"""
import sys
from typing import List, Optional, Union
try:
    from src.backend.schemas.models import VulnScan, VulnCodeIdentification
except ImportError:
    # For standalone usage - define minimal models
    from pydantic import BaseModel
    from typing import Optional, List
    
    class VulnScan(BaseModel):
        cve_id: str
        ghsa_id: str
        severity: Optional[str] = None
        related_vuln_datasource: str
        language: str
        package_name: str
        package_version: str
        fixed_version: Optional[str] = None
        cvss_v2_score: Optional[str] = None
        cvss_v2_version: Optional[str] = None
        cvss_v2_base_score: Optional[float] = None
        cvss_v2_exploitability_score: Optional[float] = None
        cvss_v2_impact_score: Optional[float] = None
        cvss_v3_score: Optional[str] = None 
        cvss_v3_version: Optional[str] = None
        cvss_v3_base_score: Optional[float] = None
        cvss_v3_exploitability_score: Optional[float] = None
        cvss_v3_impact_score: Optional[float] = None
        cvss_v4_score: Optional[str] = None
        cvss_v4_version: Optional[str] = None
        cvss_v4_base_score: Optional[float] = None
        cvss_v4_exploitability_score: Optional[float] = None
        cvss_v4_impact_score: Optional[float] = None
        epss_score: Optional[float] = None
        epss_percentile: Optional[float] = None
        summary: str
        description: str
        references: List[str]
        source_code_location: Optional[str] = None
        cwe_id: Optional[str] = None
        cwe_name: Optional[str] = None
    
    class VulnCodeIdentification(VulnScan):
        path: Optional[str] = None
        start_line: Optional[float] = None
        start_col: Optional[float] = None
        start_offset: Optional[float] = None
        end_line: Optional[float] = None
        end_col: Optional[float] = None
        end_offset: Optional[float] = None
        extra_message: Optional[str] = None
        extra_metadata_likelihood: Optional[str] = None
        extra_metadata_impact: Optional[str] = None
        extra_metadata_confidence: Optional[str] = None
        extra_metadata_vulnerability_class: Optional[str] = None
        extra_severity: Optional[str] = None
        extra_lines: Optional[str] = None
        extra_validation_state: Optional[str] = None
        extra_dataflow_trace_taint_source: Optional[str] = None
        extra_dataflow_trace_intermediate_vars: Optional[str] = None
        extra_dataflow_trace_taint_sink: Optional[str] = None
        extra_fix: Optional[str] = None
        filename: Optional[str] = None
import pandas as pd
try:
    from src.backend.workflow.vuln_identify.vuln_code_identify import (
        vuln_code_identify, 
        scan_repository as _scan_repository,
        _extract_semgrep_df,
        _run_semgrep_scan
    )
except ImportError:
    # For standalone usage
    from vuln_code_identify import (
        vuln_code_identify,
        scan_repository as _scan_repository,
        _extract_semgrep_df,
        _run_semgrep_scan
    )
import argparse
import numpy as np
import os


def identify_vulns(
        vuln_scan_results: List[VulnScan],
        dep_repos_root_dir_path: str,
        output_scans_dir_path: str | None,
        output_scans_pd_dir_path: str,
        output_pd_path: str,
        matching_strategy: str = "flexible",
        scan_all_vulnerabilities: bool = False,
        display: bool = False) -> List[VulnCodeIdentification]:
    """
    Identify vulnerable code path info from the given vulnerability scan results.
    
    This is the CVE-correlated mode that takes existing vulnerability scan results
    and attempts to locate the vulnerable code in the source repositories.
    
    Args:
        vuln_scan_results: List of vulnerability scan results
        dep_repos_root_dir_path: Root directory for cloning dependency repos
        output_scans_dir_path: Directory for raw Semgrep JSON outputs
        output_scans_pd_dir_path: Directory for processed parquet outputs
        output_pd_path: Path for final output parquet file
        matching_strategy: "strict", "flexible", or "loose" (default: "flexible")
        scan_all_vulnerabilities: If True, scan ALL vulnerabilities including fixed.
                                  If False (default), only scan unfixed vulnerabilities.
        display: If True, print the final dataframe
    
    Returns:
        List[VulnCodeIdentification]: List of identified vulnerable code paths.
    """
    # Convert vuln_scan_results to pandas DataFrame
    vuln_scan_df = pd.DataFrame([vuln.model_dump() for vuln in vuln_scan_results])
    
    # Run vulnerability code identification
    identified_vuln_df = vuln_code_identify(
        vuln_scan_df=vuln_scan_df,
        dep_repos_root_dir_path=dep_repos_root_dir_path,
        output_scans_dir_path=output_scans_dir_path,
        output_scans_pd_dir_path=output_scans_pd_dir_path,
        output_pd_path=output_pd_path,
        matching_strategy=matching_strategy,
        scan_all_vulnerabilities=scan_all_vulnerabilities
    )

    if display:
        print(identified_vuln_df)

    # Convert identified_vuln_df to List[VulnCodeIdentification]
    identified_vuln_df = identified_vuln_df.replace({np.nan: None})
    return [VulnCodeIdentification(**row) for row in identified_vuln_df.to_dict('records')]


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
    s3_output_prefix: str = None,
    display: bool = False
) -> pd.DataFrame:
    """
    Scan any repository directly with Semgrep and extract all vulnerability findings.
    
    This is the direct scan mode that can scan any arbitrary repository
    without requiring pre-existing CVE data.
    
    Args:
        repo_path: Path to the repository to scan (local path or Git URL)
        output_dir: Directory for output files
        repo_name: Name for the repository (auto-detected if not provided)
        semgrep_jobs: Number of parallel Semgrep jobs (default: 10)
        enable_dataflow_traces: Enable dataflow traces (default: True)
        semgrep_timeout: Timeout per rule in seconds (default: 600)
        max_file_size: Maximum file size to scan in bytes (default: 1000000)
        semgrep_config: Semgrep config to use (default: "auto")
        s3_bucket: S3 bucket for uploading results (optional)
        s3_output_prefix: S3 prefix for outputs (optional)
        display: If True, print the results dataframe
    
    Returns:
        DataFrame containing all Semgrep findings with extracted fields
    """
    result_df = _scan_repository(
        repo_path=repo_path,
        output_dir=output_dir,
        repo_name=repo_name,
        semgrep_jobs=semgrep_jobs,
        enable_dataflow_traces=enable_dataflow_traces,
        semgrep_timeout=semgrep_timeout,
        max_file_size=max_file_size,
        semgrep_config=semgrep_config,
        s3_bucket=s3_bucket,
        s3_output_prefix=s3_output_prefix
    )
    
    if display:
        print(result_df)
    
    return result_df


def scan_local_directory(
    dir_path: str,
    output_path: str = None,
    semgrep_jobs: int = 10,
    enable_dataflow_traces: bool = True,
    semgrep_timeout: int = 600,
    max_file_size: int = 1000000,
    semgrep_config: str = "auto"
) -> pd.DataFrame:
    """
    Scan a local directory with Semgrep and return findings as a DataFrame.
    
    This is a simplified interface for scanning a local directory without
    the full workflow (no S3, no cloning, etc.).
    
    Args:
        dir_path: Path to the directory to scan
        output_path: Path to save the results (optional)
        semgrep_jobs: Number of parallel Semgrep jobs
        enable_dataflow_traces: Enable dataflow traces
        semgrep_timeout: Timeout per rule in seconds
        max_file_size: Maximum file size to scan in bytes
        semgrep_config: Semgrep config to use
    
    Returns:
        DataFrame containing all Semgrep findings
    """
    try:
        from src.backend.utils.cmd import run_cmd
    except ImportError:
        import subprocess
        def run_cmd(cmd):
            subprocess.run(cmd, check=True)
    
    # Add safe directory for git
    abs_dir_path = os.path.abspath(dir_path)
    try:
        run_cmd(["git", "config", "--global", "--add", "safe.directory", abs_dir_path])
    except Exception:
        pass  # May not be a git repo
    
    # Run Semgrep scan
    raw_output_path = output_path.replace('.parquet', '.json') if output_path else None
    
    semgrep_result = _run_semgrep_scan(
        dir_path=dir_path,
        output_path=raw_output_path,
        num_subprocesses=semgrep_jobs,
        enable_dataflow_traces=enable_dataflow_traces,
        timeout=semgrep_timeout,
        max_file_size=max_file_size,
        config=semgrep_config
    )
    
    # Extract to DataFrame
    result_df = _extract_semgrep_df(semgrep_result, output_path=output_path)
    
    return result_df


def get_semgrep_findings_summary(df: pd.DataFrame) -> dict:
    """
    Generate a summary of Semgrep findings from a results DataFrame.
    
    Args:
        df: DataFrame containing Semgrep findings
    
    Returns:
        Dictionary with summary statistics
    """
    if df.empty:
        return {
            "total_findings": 0,
            "unique_files": 0,
            "by_severity": {},
            "by_cwe": {},
            "by_vulnerability_class": {}
        }
    
    summary = {
        "total_findings": len(df),
        "unique_files": df['path'].nunique() if 'path' in df.columns else 0,
    }
    
    # Severity breakdown
    if 'extra_severity' in df.columns:
        summary["by_severity"] = df['extra_severity'].value_counts().to_dict()
    else:
        summary["by_severity"] = {}
    
    # CWE breakdown
    if 'cwe_id' in df.columns:
        cwe_counts = df['cwe_id'].dropna().value_counts()
        summary["by_cwe"] = cwe_counts.head(10).to_dict()
    else:
        summary["by_cwe"] = {}
    
    # Vulnerability class breakdown
    if 'extra_metadata_vulnerability_class' in df.columns:
        vc_counts = df['extra_metadata_vulnerability_class'].dropna().value_counts()
        summary["by_vulnerability_class"] = vc_counts.head(10).to_dict()
    else:
        summary["by_vulnerability_class"] = {}
    
    # Dataflow trace coverage
    if 'extra_dataflow_trace_taint_source' in df.columns:
        has_trace = df['extra_dataflow_trace_taint_source'].notna() & (df['extra_dataflow_trace_taint_source'] != 'nan')
        summary["findings_with_dataflow_trace"] = int(has_trace.sum())
    else:
        summary["findings_with_dataflow_trace"] = 0
    
    return summary



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run vulnerability code identification on vulnerability scan results.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Original Makefile-compatible usage:
  python identifier.py --vuln_scan_results_path scan.parquet \\
      --dep_repos_root_dir_path ./repos \\
      --output_raw_scans_dir_path ./raw_scans \\
      --output_final_scans_dir_path ./final_scans \\
      --output_pd_path ./results.parquet

  # Direct scan mode - scan any repository
  python identifier.py --scan-repo /path/to/repo --output-dir ./results

  # Simple local directory scan
  python identifier.py --scan-dir /path/to/code --output ./findings.parquet
        """
    )
    
    # ========== ORIGINAL MAKEFILE-COMPATIBLE ARGUMENTS ==========
    # These maintain backward compatibility with the original identifier.py CLI
    parser.add_argument(
        "--vuln_scan_results_path",
        type=str,
        help="Path to the Parquet file containing vulnerability scan results."
    )
    parser.add_argument(
        "--dep_repos_root_dir_path",
        type=str,
        default="/tmp/repos",
        help="Path to the root directory where dependency repositories will be cloned."
    )
    parser.add_argument(
        "--output_raw_scans_dir_path",
        type=str,
        help="(optional) Directory path to save individual raw Semgrep scan results."
    )
    parser.add_argument(
        "--output_final_scans_dir_path",
        type=str,
        help="Directory path to save individual Semgrep scan results in Parquet format."
    )
    parser.add_argument(
        "--output_pd_path",
        type=str,
        help="Path to save the final vulnerability code identification results in Parquet format."
    )
    
    # ========== NEW EXTENDED ARGUMENTS ==========
    # Direct scan modes
    parser.add_argument(
        "--scan-repo",
        type=str,
        help="Direct scan mode: path to local repo or Git URL"
    )
    parser.add_argument(
        "--scan-dir",
        type=str,
        help="Simple scan mode: path to local directory to scan"
    )
    
    # Output options
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./identification_results",
        help="Output directory for scan results (for --scan-repo mode)"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Output file path (for --scan-dir mode)"
    )
    
    # Semgrep options
    parser.add_argument(
        "--semgrep-jobs",
        type=int,
        default=int(os.environ.get("SEMGREP_NUM_JOBS", "10")),
        help="Number of parallel Semgrep jobs"
    )
    parser.add_argument(
        "--semgrep-timeout",
        type=int,
        default=int(os.environ.get("SEMGREP_TIMEOUT", "600")),
        help="Semgrep timeout per rule in seconds"
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=int(os.environ.get("SEMGREP_MAX_FILE_SIZE", "1000000")),
        help="Maximum file size to scan in bytes"
    )
    parser.add_argument(
        "--semgrep-config",
        type=str,
        default=os.environ.get("SEMGREP_CONFIG", "auto"),
        help="Semgrep config to use"
    )
    parser.add_argument(
        "--enable-dataflow-traces",
        action="store_true",
        default=True,
        help="Enable Semgrep dataflow traces"
    )
    
    # Matching and scanning options
    parser.add_argument(
        "--matching-strategy",
        type=str,
        choices=["strict", "flexible", "loose"],
        default="flexible",
        help="CVE matching strategy (default: flexible)"
    )
    parser.add_argument(
        "--scan-all",
        action="store_true",
        default=False,
        help="Scan ALL vulnerabilities including fixed ones (default: only unfixed)"
    )
    
    # Display options - support both --display and --display=True/False
    parser.add_argument(
        "--display",
        type=lambda x: x.lower() in ('true', '1', 'yes') if isinstance(x, str) else bool(x),
        nargs='?',
        const=True,
        default=False,
        help="Display results to stdout (use --display or --display=True)"
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print summary statistics"
    )

    args = parser.parse_args()

    # ========== DETERMINE MODE AND EXECUTE ==========
    
    if args.scan_repo:
        # Direct repository scan mode
        print(f"🔍 Scanning repository: {args.scan_repo}")
        result_df = scan_repository(
            repo_path=args.scan_repo,
            output_dir=args.output_dir,
            semgrep_jobs=args.semgrep_jobs,
            enable_dataflow_traces=args.enable_dataflow_traces,
            semgrep_timeout=args.semgrep_timeout,
            max_file_size=args.max_file_size,
            semgrep_config=args.semgrep_config,
            display=args.display
        )
        
        if args.summary:
            summary = get_semgrep_findings_summary(result_df)
            print("\n📊 FINDINGS SUMMARY")
            print("=" * 40)
            for key, value in summary.items():
                print(f"{key}: {value}")
        
    elif args.scan_dir:
        # Simple local directory scan mode
        print(f"🔍 Scanning directory: {args.scan_dir}")
        output_path = args.output or os.path.join(args.output_dir, "semgrep_findings.parquet")
        
        result_df = scan_local_directory(
            dir_path=args.scan_dir,
            output_path=output_path,
            semgrep_jobs=args.semgrep_jobs,
            enable_dataflow_traces=args.enable_dataflow_traces,
            semgrep_timeout=args.semgrep_timeout,
            max_file_size=args.max_file_size,
            semgrep_config=args.semgrep_config
        )
        
        print(f"✓ Found {len(result_df)} findings")
        print(f"✓ Results saved to {output_path}")
        
        if args.display:
            print(result_df)
        
        if args.summary:
            summary = get_semgrep_findings_summary(result_df)
            print("\n📊 FINDINGS SUMMARY")
            print("=" * 40)
            for key, value in summary.items():
                print(f"{key}: {value}")
        
    elif args.vuln_scan_results_path:
        # Original CVE-correlated mode (Makefile compatible)
        if not args.output_final_scans_dir_path or not args.output_pd_path:
            parser.error("CVE mode requires --output_final_scans_dir_path and --output_pd_path")
        
        print(f"📥 Loading vulnerability scan results from {args.vuln_scan_results_path}")
        vuln_scan_df = pd.read_parquet(args.vuln_scan_results_path)
        vuln_scan_df = vuln_scan_df.replace({np.nan: None})
        vuln_scan_results = [VulnScan(**row) for row in vuln_scan_df.to_dict('records')]
        
        print(f"✓ Loaded {len(vuln_scan_results)} vulnerabilities")
        
        # Show breakdown
        fixed_count = sum(1 for v in vuln_scan_results if v.fixed_version is not None)
        unfixed_count = len(vuln_scan_results) - fixed_count
        has_source = sum(1 for v in vuln_scan_results if v.source_code_location)
        
        print(f"\n📊 Vulnerability breakdown:")
        print(f"   - Fixed (normally skipped): {fixed_count}")
        print(f"   - Unfixed (will be scanned): {unfixed_count}")
        print(f"   - Has source_code_location: {has_source}")
        
        # Handle case when there are 0 vulnerabilities
        if len(vuln_scan_results) == 0:
            print(f"\n⚠️  WARNING: No vulnerabilities found in input file!")
            print(f"   The Grype scan found no CVEs in dependencies.")
            print(f"   To scan the code directly for vulnerabilities, use --scan-repo mode instead:")
            print(f"   python identifier.py --scan-repo <repo_path> --output-dir <output_dir>")
            
            # Save empty result
            empty_df = pd.DataFrame()
            empty_df.to_parquet(args.output_pd_path)
            print(f"\n✓ Saved empty results to {args.output_pd_path}")
            sys.exit(0)
        
        if unfixed_count == 0 and not args.scan_all:
            print(f"\n⚠️  WARNING: All vulnerabilities have fixed_version set!")
            print(f"   No vulnerabilities will be scanned.")
            print(f"   Use --scan-all to scan all vulnerabilities including fixed ones.")
        
        results = identify_vulns(
            vuln_scan_results=vuln_scan_results,
            dep_repos_root_dir_path=args.dep_repos_root_dir_path,
            output_scans_dir_path=args.output_raw_scans_dir_path,
            output_scans_pd_dir_path=args.output_final_scans_dir_path,
            output_pd_path=args.output_pd_path,
            matching_strategy=args.matching_strategy,
            scan_all_vulnerabilities=args.scan_all,
            display=args.display
        )
        
        print(f"\n✅ Processed {len(results)} vulnerability records")
        
        # Count records with Semgrep data
        with_semgrep = sum(1 for r in results if r.path is not None)
        print(f"   Records with Semgrep data: {with_semgrep}")
    
    else:
        parser.error("Must specify one of: --vuln_scan_results_path, --scan-repo, or --scan-dir")