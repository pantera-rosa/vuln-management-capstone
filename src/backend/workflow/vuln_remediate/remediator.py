from typing import List, Union
from schemas.models import VulnScan, VulnCodeIdentification, VulnAssessment, Remediation  # ✅ absolute
from pandas import pd
from src.backend.workflow.vuln_remediate.generate_remediation import generate_remediation
import numpy as np
import argparse

AnyFinding = Union[VulnAssessment, VulnScan, VulnCodeIdentification]

def remediate_vulns(
        items: List[AnyFinding],
        model_id: str,
        output_pd_path: str,
        with_quantization: bool = False,
        display: bool = False) -> List[Remediation]:
    # convert items to pandas Dataframe
    vuln_df = pd.DataFrame([item.model_dump() for item in items])
    # run vuln code remediation
    remediated_vuln_df = generate_remediation(
        vuln_df=vuln_df,
        model_id=model_id,
        output_pd_path=output_pd_path,
        with_quantization=with_quantization
    )

    if display:
        print(remediated_vuln_df)

    # convert remediated_vuln_df to List[Remediation]
    remediated_vuln_df = remediated_vuln_df.replace({np.nan: None})
    return [Remediation(**row) for row in remediated_vuln_df.to_dict('records')]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run vulnerability code remediation on vulnerability scan/identification/assessment results.")
    parser.add_argument("--vuln_results_path", type=str, required=True, help="Path to the Parquet file containing vulnerability results from previous stages of the workflow.")
    parser.add_argument("--model_id", type=str, required=True, help="Model id for LLM to use in remediation generation (e.g. '01-ai/Yi-Coder-1.5B-Chat').")
    parser.add_argument("--with_quantization", type=bool, default=False, help=" (optional) If set, the specified LLM is loaded with 4-bit quantization.")
    parser.add_argument("--output_pd_path", type=str, required=True, help="Path to save the final vulnerability code remediation results in Parquet format.")
    parser.add_argument("--display", type=bool, default=False, help=" (optional) If set, display the final vulnerability code remediation dataframe to stdout after processing.")

    args = parser.parse_args()

    # load vuln results from Parquet file
    vuln_df = pd.read_parquet(args.vuln_results_path)
    vuln_df = vuln_df.replace({np.nan, None})
    vuln_results = [AnyFinding(**row) for row in vuln_df.to_dict('records')]
    remediate_vulns(
        items=vuln_results,
        model_id=args.model_id,
        with_quantization=bool(args.with_quantization),
        display=bool(args.display)
    )