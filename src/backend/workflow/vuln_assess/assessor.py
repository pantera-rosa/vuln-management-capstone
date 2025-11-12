from __future__ import annotations
from typing import List, Tuple, Optional
import os, json, math
import pandas as pd
import numpy as np
from src.backend.utils.compat import model_to_dict
from src.backend.schemas.models import VulnCodeIdentification, VulnAssessment
from src.backend.utils.df import findings_to_df, save_assessment_frames
from src.backend.workflow.vuln_assess.providers import kev_contains, fetch_epss

__all__ = ["assess_vulns", "assess_vulns_df", "assess_vulns_df_and_save"]

# ---- helpers ---------------------------------------------------------------


def _pick_cvss(v: VulnCodeIdentification) -> Optional[float]:
    # Try cvss_v2_base_score first, then cvss_v4_base_score, then cvss_v3_base_score
    if v.cvss_v2_base_score is not None:
        return float(v.cvss_v2_base_score)
    if v.cvss_v4_base_score is not None:
        return float(v.cvss_v4_base_score)
    if v.cvss_v3_base_score is not None:
        return float(v.cvss_v3_base_score)
    return None


def _normalize_cvss(score: Optional[float]) -> float:
    if score is None:
        return 0.0
    # CVSS base is 0..10 → scale to 0..100
    return max(0.0, min(100.0, (float(score) / 10.0) * 100.0))


def _label_for_score(score: float) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


# ---- core API --------------------------------------------------------------


def assess_vulns(findings: List[VulnCodeIdentification]) -> List[VulnAssessment]:
    """
    Reachability-first
    risk = 0.5*EPSS% + 0.5*CVSS_base% + 15 if reachable
    """
    results: List[VulnAssessment] = []
    for f in findings:
        cvss = _pick_cvss(f)
        cvss_norm = _normalize_cvss(cvss)

        epss = getattr(f, "epss_score", None)
        cve_id = getattr(f, "cve_id", None)
        
        # Only try to fetch EPSS if we have a valid CVE ID and no EPSS score
        if epss is None and cve_id:
            try:
                epss = fetch_epss(cve_id)  # expected 0..1
            except Exception as e:
                print(f"Warning: Failed to fetch EPSS for {cve_id}: {e}")
                epss = np.nan

        if pd.isna(epss):
            epss_norm = 0.0
        else:
            epss = float(epss)
            epss_norm = max(0.0, min(1.0, epss))

        reachable = bool(getattr(f, "reachable", False))
        risk = 0.5 * (epss_norm * 100.0) + 0.5 * cvss_norm + (15.0 if reachable else 0.0)
        risk = max(0.0, min(100.0, round(risk, 1)))
        label = _label_for_score(risk)

        rationale = f"reachable={'yes' if reachable else 'no'}, EPSS={epss_norm:.2f}, CVSS_base={cvss_norm if cvss_norm is not None else 'n/a'}, {risk} ({label})"

        base = model_to_dict(f)
        results.append(VulnAssessment(**base, kev=getattr(f, 'kev', False),
                                      risk_score=risk, risk_label=label, rationale=rationale))
    return results


# ---- DataFrame helpers -----------------------------------------------------


def assess_vulns_df(findings: List[VulnCodeIdentification]) -> pd.DataFrame:
    """
    Run enrichment and return a tidy pandas DataFrame.
    IMPORTANT: This function preserves ALL fields from VulnCodeIdentification.
    """
    assessed = assess_vulns(findings)
    df = findings_to_df(assessed)
    
    # Define preferred column order (most important first)
    # All columns not in this list will be appended at the end
    preferred_cols = [
        # Key identifiers
        "cve_id",
        "ghsa_id",
        "package_name",
        "package_version",
        "fixed_version",
        
        # Assessment results (NEW - the whole point of this workflow!)
        "risk_score",
        "risk_label",
        "kev",
        "rationale",
        
        # Vulnerability info
        "severity",
        "language",
        "related_vuln_datasource",
        
        # CVSS scores
        "cvss_v4_score",
        "cvss_v4_version",
        "cvss_v4_base_score",
        "cvss_v4_exploitability_score",
        "cvss_v4_impact_score",
        "cvss_v3_score",
        "cvss_v3_version",
        "cvss_v3_base_score",
        "cvss_v3_exploitability_score",
        "cvss_v3_impact_score",
        "cvss_v2_score",
        "cvss_v2_version",
        "cvss_v2_base_score",
        "cvss_v2_exploitability_score",
        "cvss_v2_impact_score",
        
        # EPSS scores
        "epss_score",
        "epss_percentile",
        
        # Code location info (CRITICAL for remediation!)
        "path",
        "filename",
        "start_line",
        "end_line",
        "start_col",
        "end_col",
        "start_offset",
        "end_offset",
        
        # Extra metadata from code identification
        "extra_lines",
        "extra_message",
        "extra_metadata_likelihood",
        "extra_metadata_impact",
        "extra_metadata_confidence",
        "extra_metadata_vulnerability_class",
        "extra_severity",
        "extra_validation_state",
        "extra_dataflow_trace_taint_source",
        "extra_dataflow_trace_intermediate_vars",
        "extra_dataflow_trace_taint_sink",
        "extra_fix",
        
        # CWE info
        "cwe_id",
        "cwe_name",
        
        # Source info
        "source_code_location",
        
        # Descriptions (verbose, so put at end)
        "summary",
        "description",
        "references",
    ]
    
    # Order columns: preferred columns first (that exist), then remaining columns
    ordered_cols = [c for c in preferred_cols if c in df.columns]
    remaining_cols = [c for c in df.columns if c not in preferred_cols]
    final_cols = ordered_cols + remaining_cols
    
    # Return with all columns preserved
    return df[final_cols]


def assess_vulns_df_and_save(
    findings: List[VulnCodeIdentification],
    out_dir: str = "artifacts/assessments",
) -> Tuple[pd.DataFrame, dict]:
    """
    Enrich → DataFrame → save CSV (+ Parquet if available). Return (df, paths).
    All fields from VulnCodeIdentification are preserved in the output.
    """
    df = assess_vulns_df(findings)
    paths = save_assessment_frames(df, out_dir=out_dir)
    return df, paths


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Run vulnerability assessment on vulnerability code identification results."
    )
    parser.add_argument(
        "--vuln_identify_results_path",
        type=str,
        required=True,
        help="Path to the Parquet file containing vulnerability code identification results from vuln_identify workflow."
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        default="artifacts/assessments",
        help="Directory path to save the vulnerability assessment results (CSV and Parquet)."
    )
    parser.add_argument(
        "--display",
        action="store_true",
        default=False,
        help="(optional) If set, display the vulnerability assessment dataframe to stdout after processing."
    )
    
    args = parser.parse_args()
    
    # Load vuln_identify results from Parquet file
    print(f"Loading vulnerability identification results from: {args.vuln_identify_results_path}")
    vuln_identify_df = pd.read_parquet(args.vuln_identify_results_path)
    vuln_identify_df = vuln_identify_df.replace({np.nan: None})
    
    # Convert DataFrame to List[VulnCodeIdentification]
    vuln_findings = [VulnCodeIdentification(**row) for row in vuln_identify_df.to_dict('records')]
    print(f"Loaded {len(vuln_findings)} vulnerability findings for assessment")
    
    # Run assessment and save results
    print("Running vulnerability assessment...")
    df, paths = assess_vulns_df_and_save(
        findings=vuln_findings,
        out_dir=args.output_dir
    )
    
    # Print summary
    print(f"\n{'='*80}")
    print(f"Assessment Summary")
    print(f"{'='*80}")
    print(f"Total vulnerabilities assessed: {len(df)}")
    if 'risk_label' in df.columns:
        print(f"\nRisk Distribution:")
        risk_counts = df['risk_label'].value_counts()
        for label in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = risk_counts.get(label, 0)
            print(f"  {label}: {count}")
    
    print(f"\nColumns preserved: {len(df.columns)}")
    print(f"  - VulnScan base fields: {len([c for c in df.columns if c in ['cve_id', 'ghsa_id', 'package_name', 'severity', 'cvss_v3_base_score', 'epss_score']])}")
    print(f"  - Code identification fields: {len([c for c in df.columns if c in ['path', 'start_line', 'end_line', 'extra_lines', 'extra_dataflow_trace_taint_source']])}")
    print(f"  - Assessment fields: {len([c for c in df.columns if c in ['risk_score', 'risk_label', 'kev', 'rationale']])}")
    
    if args.display:
        print(f"\n{'='*80}")
        print("VULNERABILITY ASSESSMENT RESULTS")
        print(f"{'='*80}")
        print(df)
    
    print(f"\nAssessment complete! Results saved to:")
    for key, path in paths.items():
        print(f"  {key}: {path}")