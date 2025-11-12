from typing import List
from src.backend.schemas.models import VulnScan, VulnCodeIdentification
import pandas as pd
from src.backend.workflow.vuln_identify.vuln_code_identify import vuln_code_identify
import argparse
import numpy as np

def identify_vulns(
        vuln_scan_results: List[VulnScan],
        dep_repos_root_dir_path: str,
        output_scans_dir_path: str | None,
        output_scans_pd_dir_path: str,
        output_pd_path: str,
        display: bool = False) -> List[VulnCodeIdentification]:
    """
    Identify vulnerable code path info from the given vulnerability scan results.
    Returns:
        List[VulnCodeIdentification]: List of identified vulnerable code paths.
    """
    # convert vuln_scan_results to pandas DataFrame
    vuln_scan_df = pd.DataFrame([vuln.model_dump() for vuln in vuln_scan_results])
    # run vulnerability code identification
    identified_vuln_df = vuln_code_identify(
        vuln_scan_df=vuln_scan_df,
        dep_repos_root_dir_path=dep_repos_root_dir_path,
        output_scans_dir_path=output_scans_dir_path,
        output_scans_pd_dir_path=output_scans_pd_dir_path,
        output_pd_path=output_pd_path
    )

    if display:
        print(identified_vuln_df)

    # convert identified_vuln_df to List[VulnCodeIdentification]
    identified_vuln_df = identified_vuln_df.replace({np.nan: None})
    return [VulnCodeIdentification(**row) for row in identified_vuln_df.to_dict('records')]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run vulnerability code identification on vulnerability scan results.")
    parser.add_argument("--vuln_scan_results_path", type=str, required=True, help="Path to the Parquet file containing vulnerability scan results.")
    parser.add_argument("--dep_repos_root_dir_path", type=str, required=True, help="Path to the root directory where the unfixed vulnerable OSS dependency repositories will be cloned.")
    parser.add_argument("--output_raw_scans_dir_path", type=str, help="(optional) Directory path to save individual vulnerability code identification scan results.")
    parser.add_argument("--output_final_scans_dir_path", type=str, required=True, help="Directory path to save individual vulnerability code identification scan results in Parquet format.")
    parser.add_argument("--output_pd_path", type=str, required=True, help="Path to save the final vulnerability code identification results in Parquet format.")
    parser.add_argument("--display", type=bool, default=False, help=" (optional) If set, display the final vulnerability code identification dataframe to stdout after processing.")
    
    args = parser.parse_args()

    # load vuln_scan_results from Parquet file
    vuln_scan_df = pd.read_parquet(args.vuln_scan_results_path)
    vuln_scan_df = vuln_scan_df.replace({np.nan: None})
    vuln_scan_results = [VulnScan(**row) for row in vuln_scan_df.to_dict('records')]
    identify_vulns(
        vuln_scan_results=vuln_scan_results,
        dep_repos_root_dir_path=args.dep_repos_root_dir_path,
        output_scans_dir_path=args.output_raw_scans_dir_path,
        output_scans_pd_dir_path=args.output_final_scans_dir_path,
        output_pd_path=args.output_pd_path,
        display=bool(args.display)
    )