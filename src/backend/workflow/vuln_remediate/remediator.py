"""
Enhanced Remediator with Reachability-Aware Prioritization

This module provides the command-line interface for running remediation
with reachability analysis integration.
"""

from __future__ import annotations
from typing import List
from src.backend.schemas.models import VulnAssessment, Remediation
import pandas as pd
from src.backend.workflow.vuln_remediate.generate_remediation import (
    generate_remediation_with_reachability
)
from src.backend.utils.df import findings_to_df
import numpy as np
import argparse


def remediate_vulns_with_reachability(
        items: List[VulnAssessment],
        model_id: str,
        output_pd_path: str,
        dep_repos_root_dir_path: str,
        with_quantization: bool = False,
        max_remediations: int | None = None,
        only_reachable: bool = False,
        display: bool = False) -> List[Remediation]:
    """
    Run reachability-aware vulnerability remediation.
    
    Args:
        items: List of vulnerability assessments with reachability info
        model_id: LLM model ID for code generation
        output_pd_path: Path to save remediation results
        dep_repos_root_dir_path: Root directory for cloned repositories
        with_quantization: Whether to use 4-bit quantization
        max_remediations: Optional limit on number of remediations to generate
        only_reachable: If True, only remediate direct/indirect vulnerabilities
        display: Whether to display results
        
    Returns:
        List of Remediation objects
    """
    # Convert items to pandas DataFrame
    vuln_df = findings_to_df(items)
    
    # Run reachability-aware remediation
    remediated_vuln_df, output_paths = generate_remediation_with_reachability(
        vuln_df=vuln_df,
        model_id=model_id,
        output_pd_path=output_pd_path,
        dep_repos_root_dir_path=dep_repos_root_dir_path,
        with_quantization=with_quantization,
        max_remediations=max_remediations,
        only_reachable=only_reachable
    )

    if display:
        print("\n" + "="*80)
        print("REMEDIATION RESULTS")
        print("="*80)
        # Display key columns
        display_cols = [
            'remediation_priority', 'reachability_level', 'cve_id', 
            'package_name', 'risk_label', 'recommendation'
        ]
        available_cols = [col for col in display_cols if col in remediated_vuln_df.columns]
        print(remediated_vuln_df[available_cols].to_string(index=False))
        
        print(f"\n📂 Output Files:")
        for file_type, path in output_paths.items():
            if path:
                print(f"   {file_type}: {path}")

    # Convert remediated_vuln_df to List[Remediation]
    remediated_vuln_df = remediated_vuln_df.replace({np.nan: None})
    return [Remediation(**row) for row in remediated_vuln_df.to_dict('records')]


# Backward compatibility: alias
remediate_vulns = remediate_vulns_with_reachability


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run reachability-aware vulnerability remediation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Remediate all vulnerabilities with reachability prioritization
  python remediator_enhanced.py --vuln_results_path assessments.parquet \
      --dep_repos_root_dir_path repos/ --model_id 01-ai/Yi-Coder-1.5B-Chat \
      --output_pd_path remediations.parquet
  
  # Remediate only direct/indirect reachable vulnerabilities
  python remediator_enhanced.py --vuln_results_path assessments.parquet \
      --dep_repos_root_dir_path repos/ --model_id 01-ai/Yi-Coder-1.5B-Chat \
      --output_pd_path remediations.parquet --only-reachable
  
  # Limit to top 10 highest priority vulnerabilities
  python remediator_enhanced.py --vuln_results_path assessments.parquet \
      --dep_repos_root_dir_path repos/ --model_id 01-ai/Yi-Coder-1.5B-Chat \
      --output_pd_path remediations.parquet --max-remediations 10
        """
    )
    
    parser.add_argument(
        "--vuln_results_path",
        type=str,
        required=True,
        help="Path to the Parquet file containing vulnerability assessment results"
    )
    
    parser.add_argument(
        "--dep_repos_root_dir_path",
        type=str,
        required=True,
        help="Path to the root directory where vulnerable OSS dependency repositories are cloned"
    )
    
    parser.add_argument(
        "--model_id",
        type=str,
        required=True,
        help="Model ID for LLM to use in remediation generation (e.g. 01-ai/Yi-Coder-1.5B-Chat)"
    )
    
    parser.add_argument(
        "--output_pd_path",
        type=str,
        required=True,
        help="Path to save the final vulnerability remediation results in Parquet format"
    )
    
    parser.add_argument(
        "--with_quantization",
        action='store_true',
        help="If set, the specified LLM is loaded with 4-bit quantization"
    )
    
    parser.add_argument(
        "--max-remediations",
        type=int,
        default=None,
        help="Maximum number of remediations to generate (prioritizes by reachability)"
    )
    
    parser.add_argument(
        "--only-reachable",
        action='store_true',
        help="Only generate remediations for direct and indirect reachable vulnerabilities"
    )
    
    parser.add_argument(
        "--display",
        action='store_true',
        help="Display the final vulnerability remediation dataframe after processing"
    )

    args = parser.parse_args()

    # Load vulnerability results from Parquet file
    vuln_df = pd.read_parquet(args.vuln_results_path)
    vuln_df = vuln_df.replace({np.nan: None})
    vuln_results = [VulnAssessment(**row) for row in vuln_df.to_dict('records')]
    
    # Run remediation
    remediate_vulns_with_reachability(
        items=vuln_results,
        model_id=args.model_id,
        with_quantization=args.with_quantization,
        max_remediations=args.max_remediations,
        only_reachable=args.only_reachable,
        output_pd_path=args.output_pd_path,
        dep_repos_root_dir_path=args.dep_repos_root_dir_path,
        display=args.display
    )