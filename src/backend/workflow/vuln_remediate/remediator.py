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
        display: bool = False,
        save_csv: bool = True,
        use_sagemaker: bool = False,
        sagemaker_endpoint_name: str = None,
        aws_region: str = None) -> List[Remediation]:
    """
    Run vulnerability remediation workflow.
    
    Args:
        items: List of vulnerability assessments
        model_id: LLM model ID for remediation generation
        output_pd_path: Path to save parquet results
        dep_repos_root_dir_path: Root directory for dependency repos
        with_quantization: Whether to use 4-bit quantization
        display: Whether to display results
        save_csv: Whether to also save results as CSV (default: True)
        use_sagemaker: Whether to use SageMaker endpoint instead of local model
        sagemaker_endpoint_name: Name of SageMaker endpoint (used if use_sagemaker=True)
        aws_region: AWS region for SageMaker (defaults to us-east-1)
    
    Returns:
        List of Remediation objects
    """
    # convert items to pandas Dataframe
    vuln_df = findings_to_df(items)
    # run vuln code remediation
    remediated_vuln_df = generate_remediation(
        vuln_df=vuln_df,
        model_id=model_id,
        output_pd_path=output_pd_path,
        dep_repos_root_dir_path=dep_repos_root_dir_path,
        with_quantization=with_quantization,
        save_csv=save_csv,
        use_sagemaker=use_sagemaker,
        sagemaker_endpoint_name=sagemaker_endpoint_name,
        aws_region=aws_region
    )

    if display:
        print(remediated_vuln_df)

    # convert remediated_vuln_df to List[Remediation]
    remediated_vuln_df = remediated_vuln_df.replace({np.nan: None})
    return [Remediation(**row) for row in remediated_vuln_df.to_dict('records')]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run vulnerability code remediation on vulnerability scan/identification/assessment results.")
    parser.add_argument("--vuln_results_path", type=str, required=True, help="Path to the Parquet file containing vulnerability results from previous stages of the workflow.")
    parser.add_argument("--dep_repos_root_dir_path", type=str, required=True, help="Path to the root directory where the unfixed vulnerable OSS dependency repositories are cloned.")
    parser.add_argument("--model_id", type=str, required=True, help="Model id for LLM to use in remediation generation (e.g. 01-ai/Yi-Coder-1.5B-Chat).")
    parser.add_argument("--with_quantization", type=bool, default=False, help=" (optional) If set, the specified LLM is loaded with 4-bit quantization.")
    parser.add_argument("--output_pd_path", type=str, required=True, help="Path to save the final vulnerability code remediation results in Parquet format.")
    parser.add_argument("--display", type=bool, default=False, help=" (optional) If set, display the final vulnerability code remediation dataframe to stdout after processing.")
    parser.add_argument("--save_csv", type=bool, default=True, help=" (optional) If set, also save results as CSV alongside Parquet file.")
    parser.add_argument("--use_sagemaker", type=bool, default=False, help=" (optional) If set, use SageMaker endpoint instead of local LLM model.")
    parser.add_argument("--sagemaker_endpoint_name", type=str, default=None, help=" (optional) Name of the SageMaker endpoint to use (required if --use_sagemaker is True).")
    parser.add_argument("--aws_region", type=str, default="us-east-1", help=" (optional) AWS region for SageMaker endpoint (default: us-east-1).")

    args = parser.parse_args()

    # load vuln results from Parquet file
    vuln_df = pd.read_parquet(args.vuln_results_path)
    vuln_df = vuln_df.replace({np.nan: None})
    vuln_results = [VulnAssessment(**row) for row in vuln_df.to_dict('records')]
    remediate_vulns(
        items=vuln_results,
        model_id=args.model_id,
        with_quantization=bool(args.with_quantization),
        output_pd_path=args.output_pd_path,
        dep_repos_root_dir_path=args.dep_repos_root_dir_path,
        display=bool(args.display),
        save_csv=bool(args.save_csv),
        use_sagemaker=bool(args.use_sagemaker),
        sagemaker_endpoint_name=args.sagemaker_endpoint_name,
        aws_region=args.aws_region
    )