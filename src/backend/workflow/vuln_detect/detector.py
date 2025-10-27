import os
from typing import List, Optional
import argparse
from src.backend.schemas.models import VulnScan
from src.backend.workflow.vuln_detect.vuln_scan import perform_vuln_scan, extract_sbom
from src.backend.utils.cmd import run_cmd
import numpy as np

def detect_vulns(
    repo_url: Optional[str],
    dir_path: Optional[str],
    sbom_path: str,
    output_raw_scan_path: Optional[str],
    output_final_scan_path: str,
    display: bool = False,
) -> List[VulnScan]:
    # Validate args locally instead of relying on an external `parser` object.
    if repo_url and not dir_path:
        # prefer raising an exception so callers can handle it; argparse's parser.error
        # is not available here when the function is imported programmatically.
        raise ValueError("--dir_path must be provided if --repo_url is specified.")

    # if repo_url is provided and dir_path doesn't exist or is empty, clone the repo
    if repo_url and dir_path and (not os.path.exists(dir_path) or not os.listdir(dir_path)):
        # clone the repo to dir_path
        run_cmd(["git", "clone", repo_url, dir_path])

    if dir_path:
        # extract sbom first
        print(f"Extracting SBOM from directory: {dir_path} to {sbom_path}")
        extract_sbom(dir_path, sbom_path)
    print(f"Performing vulnerability scan on SBOM: {sbom_path}")
    final_df = perform_vuln_scan(
		sbom_path=sbom_path,
		output_scan_path=output_raw_scan_path,
		output_pd_path=output_final_scan_path
	)
    print(f"Vulnerability scan completed. Saved to {output_final_scan_path}.")

    if display:
        print(final_df)

    # convert final_df to List[VulnScan]
    final_df=final_df.replace({np.nan: None})
    vulns=[VulnScan(**row) for row in final_df.to_dict('records')]
    return vulns

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run vulnerability detection on a given repo.")
    parser.add_argument("--repo_url", type=str, help="(optional) GitHub URL of the repo to analyze.")
    parser.add_argument("--dir_path", type=str, help="(optional) Path to the directory to clone the repo to. Must be provided if repo_url is provided.")
    parser.add_argument("--sbom_path", type=str, required=True, help="If dir_path is provided, this is the path to save the extracted SBOM. Else, the program will expect an SBOM file located at this path and will use it for scanning. Should end with .spdx.json.")
    parser.add_argument("--output_raw_scan_path", type=str, help="(optional) JSON path to save the raw vulnerability scan results.")
    parser.add_argument("--output_final_scan_path", type=str, required=True, help="Parquet path to save the final vulnerability scan results.")
    parser.add_argument("--display", type=bool, default=False, help=" (optional) If set, display the final vulnerability scan dataframe to stdout after processing.")

    args = parser.parse_args()

    detect_vulns(
        repo_url=args.repo_url,
        dir_path=args.dir_path,
        sbom_path=args.sbom_path,
        output_raw_scan_path=args.output_raw_scan_path,
        output_final_scan_path=args.output_final_scan_path,
        display=bool(args.display),
    )