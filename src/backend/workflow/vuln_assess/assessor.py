"""
Enhanced Vulnerability Assessor with Reachability Analysis

This module extends the original assessor with comprehensive reachability analysis
based on Fluid Attacks methodology. It provides more accurate risk scoring by
considering whether vulnerabilities are actually reachable in the application context.
"""

from __future__ import annotations
from typing import List, Tuple, Optional
import os
import pandas as pd
import numpy as np
from src.backend.utils.compat import model_to_dict
from src.backend.schemas.models import VulnCodeIdentification, VulnAssessment
from src.backend.utils.df import findings_to_df, save_assessment_frames
from src.backend.workflow.vuln_assess.providers import kev_contains, fetch_epss

# Import the reachability analyzer
from src.backend.workflow.vuln_assess.reachability import (
    analyze_vulnerability_reachability,
    ReachabilityLevel,
    get_reachability_multiplier
)

__all__ = ["assess_vulns", "assess_vulns_df", "assess_vulns_df_and_save", "assess_vulns_with_reachability"]


# ---- Helpers ---------------------------------------------------------------

def _pick_cvss(v: VulnCodeIdentification) -> Optional[float]:
    """Pick the best available CVSS score."""
    if v.cvss_v2_base_score is not None:
        return float(v.cvss_v2_base_score)
    if v.cvss_v4_base_score is not None:
        return float(v.cvss_v4_base_score)
    if v.cvss_v3_base_score is not None:
        return float(v.cvss_v3_base_score)
    return None


def _normalize_cvss(score: Optional[float]) -> float:
    """Normalize CVSS score to 0-100 range."""
    if score is None:
        return 0.0
    return max(0.0, min(100.0, (float(score) / 10.0) * 100.0))


def _label_for_score(score: float) -> str:
    """Convert numerical risk score to risk label."""
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


# ---- Enhanced Assessment with Reachability ---------------------------------

def assess_vulns_with_reachability(
    findings: List[VulnCodeIdentification],
    enable_reachability: bool = True
) -> List[VulnAssessment]:
    """
    Enhanced vulnerability assessment with comprehensive reachability analysis.
    
    Risk Scoring Formula:
    ---------------------
    If reachability is enabled:
        base_risk = (CVSS_normalized * 0.4) + (EPSS_normalized * 0.3)
        reachability_boost = reachability_score * 0.3
        risk_score = (base_risk + reachability_boost) * reachability_multiplier
    
    Otherwise (legacy):
        risk = 0.5 * EPSS% + 0.5 * CVSS% + (15 if reachable else 0)
    
    Args:
        findings: List of vulnerability findings with code identification
        enable_reachability: Whether to use enhanced reachability analysis
    
    Returns:
        List of assessed vulnerabilities with risk scores and reachability info
    """
    results: List[VulnAssessment] = []
    
    for f in findings:
        # Get CVSS score
        cvss = _pick_cvss(f)
        cvss_norm = _normalize_cvss(cvss)
        
        # Get or fetch EPSS score
        epss = getattr(f, "epss_score", None)
        cve_id = getattr(f, "cve_id", None)
        
        if epss is None and cve_id:
            try:
                epss = fetch_epss(cve_id)
            except Exception as e:
                print(f"Warning: Failed to fetch EPSS for {cve_id}: {e}")
                epss = np.nan
        
        if pd.isna(epss):
            epss_norm = 0.0
        else:
            epss = float(epss)
            epss_norm = max(0.0, min(1.0, epss))
        
        # Get KEV status
        kev = kev_contains(cve_id) if cve_id else False
        
        # --- REACHABILITY ANALYSIS ---
        if enable_reachability:
            # Perform comprehensive reachability analysis
            vuln_dict = model_to_dict(f)
            reachability_results = analyze_vulnerability_reachability(vuln_dict)
            
            reachability_level = reachability_results["reachability_level"]
            reachability_score = reachability_results["reachability_score"]
            reachability_confidence = reachability_results["confidence"]
            reachability_rationale = reachability_results["rationale"]
            dataflow_exists = reachability_results["dataflow_exists"]
            
            # Calculate risk using enhanced formula
            # Base risk from CVSS (40%) and EPSS (30%)
            base_risk = (cvss_norm * 0.4) + (epss_norm * 100.0 * 0.3)
            
            # Reachability contribution (30% of score)
            reachability_contribution = reachability_score * 0.3
            
            # Apply reachability multiplier
            multiplier = get_reachability_multiplier(reachability_level)
            
            # Calculate final risk score
            risk = (base_risk + reachability_contribution) * multiplier
            
            # Add KEV boost if applicable
            if kev:
                risk += 10.0
            
            # Normalize to 0-100
            risk = max(0.0, min(100.0, round(risk, 1)))
            
            # Generate comprehensive rationale
            rationale = (
                f"Reachability: {reachability_level.value} "
                f"(score: {reachability_score:.1f}, confidence: {reachability_confidence:.2f}), "
                f"CVSS: {cvss_norm:.1f}, EPSS: {epss_norm:.3f}, "
                f"KEV: {'yes' if kev else 'no'}, "
                f"Dataflow: {'complete' if dataflow_exists else 'incomplete'} "
                f"→ Risk: {risk:.1f} ({_label_for_score(risk)})"
            )
            
            # Create assessment with reachability fields
            base = model_to_dict(f)
            assessment = VulnAssessment(
                **base,
                kev=kev,
                risk_score=risk,
                risk_label=_label_for_score(risk),
                rationale=rationale,
                # Add reachability-specific fields if your model supports them
                # Otherwise they'll be in rationale
            )
            
        else:
            # Legacy simple reachability scoring (backward compatible)
            reachable = bool(getattr(f, "reachable", False))
            risk = 0.5 * (epss_norm * 100.0) + 0.5 * cvss_norm + (15.0 if reachable else 0.0)
            
            # Add KEV boost
            if kev:
                risk += 10.0
            
            risk = max(0.0, min(100.0, round(risk, 1)))
            
            rationale = (
                f"reachable={'yes' if reachable else 'no'}, "
                f"EPSS={epss_norm:.2f}, CVSS_base={cvss_norm if cvss_norm is not None else 'n/a'}, "
                f"KEV={'yes' if kev else 'no'}, "
                f"{risk} ({_label_for_score(risk)})"
            )
            
            base = model_to_dict(f)
            assessment = VulnAssessment(
                **base,
                kev=kev,
                risk_score=risk,
                risk_label=_label_for_score(risk),
                rationale=rationale
            )
        
        results.append(assessment)
    
    return results


# ---- Original API (now calls enhanced version) -----------------------------

def assess_vulns(findings: List[VulnCodeIdentification]) -> List[VulnAssessment]:
    """
    Original assess_vulns function, now using enhanced reachability analysis.
    Maintains backward compatibility.
    """
    return assess_vulns_with_reachability(findings, enable_reachability=True)


# ---- DataFrame Helpers ------------------------------------------------------

def assess_vulns_df(
    findings: List[VulnCodeIdentification],
    enable_reachability: bool = True
) -> pd.DataFrame:
    """
    Run enrichment with reachability analysis and return a tidy pandas DataFrame.
    
    Args:
        findings: List of vulnerability findings
        enable_reachability: Whether to use enhanced reachability analysis
    
    Returns:
        DataFrame with assessment results
    """
    assessed = assess_vulns_with_reachability(findings, enable_reachability)
    df = findings_to_df(assessed)
    return df


def assess_vulns_df_and_save(
    findings: List[VulnCodeIdentification],
    out_dir: str = "artifacts/assessments",
    enable_reachability: bool = True
) -> Tuple[pd.DataFrame, dict]:
    """
    Enrich with reachability → DataFrame → save CSV + Parquet.
    
    Args:
        findings: List of vulnerability findings
        out_dir: Output directory for assessment results
        enable_reachability: Whether to use enhanced reachability analysis
    
    Returns:
        Tuple of (DataFrame, output_paths_dict)
    """
    df = assess_vulns_df(findings, enable_reachability)
    paths = save_assessment_frames(df, out_dir=out_dir)
    return df, paths


# ---- Statistics and Reporting -----------------------------------------------

def generate_reachability_report(assessed_df: pd.DataFrame) -> dict:
    """
    Generate a summary report of reachability analysis results.
    
    Args:
        assessed_df: DataFrame with assessed vulnerabilities
    
    Returns:
        Dictionary with reachability statistics
    """
    report = {
        "total_vulnerabilities": len(assessed_df),
        "by_risk_label": assessed_df["risk_label"].value_counts().to_dict(),
        "avg_risk_score": float(assessed_df["risk_score"].mean()),
        "max_risk_score": float(assessed_df["risk_score"].max()),
        "min_risk_score": float(assessed_df["risk_score"].min()),
    }
    
    # Try to extract reachability levels from rationale if present
    if "rationale" in assessed_df.columns:
        reachability_counts = {}
        for level in [
            ReachabilityLevel.DIRECT,
            ReachabilityLevel.INDIRECT,
            ReachabilityLevel.UNREACHABLE,
            ReachabilityLevel.UNKNOWN
        ]:
            count = assessed_df["rationale"].str.contains(
                level.value,
                case=False,
                na=False
            ).sum()
            reachability_counts[level.value] = int(count)
        
        report["by_reachability_level"] = reachability_counts
    
    return report