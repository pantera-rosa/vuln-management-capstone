from __future__ import annotations
from typing import List
from src.backend.schemas.models import VulnAssessment, Remediation  # ✅ absolute
import pandas as pd
from src.backend.workflow.vuln_remediate.generate_remediation import generate_remediation
from src.backend.utils.df import findings_to_df
import numpy as np
import argparse

def remediate_vulns(
        items: List[VulnAssessment],
        model_id: str,
        output_pd_path: str,
        dep_repos_root_dir_path: str,
        with_quantization: bool = False,
        display: bool = False) -> List[Remediation]:
    # convert items to pandas Dataframe
    vuln_df = findings_to_df(items)
    
    # run vuln code remediation
    remediated_vuln_df = generate_remediation(
        vuln_df=vuln_df,
        model_id=model_id,
        output_pd_path=output_pd_path,
        dep_repos_root_dir_path=dep_repos_root_dir_path,
        with_quantization=with_quantization
    )

    # ✅ Handle missing or None values in recommendation column
    if 'recommendation' not in remediated_vuln_df.columns:
        remediated_vuln_df['recommendation'] = "Remediation not available"
    else:
        # Replace None and NaN with default message
        remediated_vuln_df['recommendation'] = (
            remediated_vuln_df['recommendation']
            .fillna("Remediation not available")
            .replace({None: "Remediation not available", '': "Remediation not available"})
        )

    if display:
        print(remediated_vuln_df)

    # convert remediated_vuln_df to List[Remediation]
    remediated_vuln_df = remediated_vuln_df.replace({np.nan: None})
    
    return [Remediation(**row) for row in remediated_vuln_df.to_dict('records')]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run vulnerability code remediation on vulnerability scan/identification/assessment results.")
    parser.add_argument("--vuln_results_path", type=str, required=True, help="Path to the Parquet or CSV file containing vulnerability results from previous stages of the workflow.")
    parser.add_argument("--dep_repos_root_dir_path", type=str, required=True, help="Path to the root directory where the unfixed vulnerable OSS dependency repositories are cloned.")
    parser.add_argument("--model_id", type=str, required=True, help="Model id for LLM to use in remediation generation (e.g. 01-ai/Yi-Coder-1.5B-Chat).")
    parser.add_argument("--with_quantization", type=bool, default=False, help=" (optional) If set, the specified LLM is loaded with 4-bit quantization.")
    parser.add_argument("--output_pd_path", type=str, required=True, help="Path to save the final vulnerability code remediation results in Parquet format.")
    parser.add_argument("--display", type=bool, default=False, help=" (optional) If set, display the final vulnerability code remediation dataframe to stdout after processing.")

    args = parser.parse_args()

    # ✅ Load vuln results from Parquet or CSV file
    print(f"📂 Loading vulnerability results from: {args.vuln_results_path}")
    
    if args.vuln_results_path.endswith('.parquet'):
        vuln_df = pd.read_parquet(args.vuln_results_path)
    elif args.vuln_results_path.endswith('.csv'):
        # ✅ Read CSV with proper handling
        vuln_df = pd.read_csv(args.vuln_results_path, keep_default_na=True)
    else:
        raise ValueError(f"Unsupported file format: {args.vuln_results_path}. Must be .parquet or .csv")
    
    print(f"✅ Loaded {len(vuln_df)} vulnerability records")
    print(f"📋 Columns: {vuln_df.columns.tolist()}")
    
    # ✅ Debug: Check for NaN values in critical columns
    critical_cols = ['path', 'start_line', 'end_line', 'source_code_location']
    for col in critical_cols:
        if col in vuln_df.columns:
            non_null = vuln_df[col].notna().sum()
            print(f"   {col}: {non_null}/{len(vuln_df)} non-null values")
    
    vuln_df = vuln_df.replace({np.nan: None})
    vuln_results = [VulnAssessment(**row) for row in vuln_df.to_dict('records')]
    
    remediate_vulns(
        items=vuln_results,
        model_id=args.model_id,
        with_quantization=bool(args.with_quantization),
        output_pd_path=args.output_pd_path,
        dep_repos_root_dir_path=args.dep_repos_root_dir_path,
        display=bool(args.display)
    )