from __future__ import annotations
from typing import List, Tuple, Optional
import math
import pandas as pd
from src.backend.utils.compat import model_to_dict
from src.backend.schemas.models import VulnScan, VulnAssessment
from src.backend.utils.df import findings_to_df, save_assessment_frames
from src.backend.workflow.vuln_assess.providers import kev_contains, fetch_epss

__all__ = ["assess_vulns", "assess_vulns_df", "assess_vulns_df_and_save"]

# ---- helpers ---------------------------------------------------------------


def _pick_cvss(v: VulnScan) -> Optional[float]:
    # Try cvss_v2_score first (it's a float)
    if v.cvss_v2_score is not None:
        return float(v.cvss_v2_score)

    # Try to parse CVSS v3 vector string
    if v.cvss_v3_score is not None and isinstance(v.cvss_v3_score, str):
        return _parse_cvss_v3_vector(v.cvss_v3_score)

    # Try to parse CVSS v4 vector string
    if v.cvss_v4_vector is not None and isinstance(v.cvss_v4_vector, str):
        return _parse_cvss_v4_vector(v.cvss_v4_vector)

    return None


def _parse_cvss_v3_vector(vector: str) -> Optional[float]:
    """Parse CVSS v3 vector string and return base score."""
    try:
        # Extract the vector part after "CVSS:3.x/"
        if "CVSS:3." in vector:
            vector_part = vector.split("CVSS:3.")[1].split("/")[1:]  # Skip version part
        else:
            vector_part = vector.split("/")

        # Parse the vector components
        metrics = {}
        for component in vector_part:
            if ":" in component:
                key, value = component.split(":", 1)
                metrics[key] = value

        # Calculate base score from metrics
        return _calculate_cvss_v3_base_score(metrics)
    except Exception:
        return None


def _parse_cvss_v4_vector(vector: str) -> Optional[float]:
    """Parse CVSS v4 vector string and return base score."""
    try:
        # Extract the vector part after "CVSS:4.0/"
        if "CVSS:4.0/" in vector:
            vector_part = vector.split("CVSS:4.0/")[1].split("/")
        else:
            vector_part = vector.split("/")

        # Parse the vector components
        metrics = {}
        for component in vector_part:
            if ":" in component:
                key, value = component.split(":", 1)
                metrics[key] = value

        # Calculate base score from metrics
        return _calculate_cvss_v4_base_score(metrics)
    except Exception:
        return None


def _calculate_cvss_v3_base_score(metrics: dict) -> float:
    """Calculate CVSS v3 base score from metrics."""
    # Simplified CVSS v3 base score calculation
    # This is a basic implementation - in production you'd want a full CVSS library

    # Impact sub-score calculation
    c = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get("C", "N"), 0.0)
    i = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get("I", "N"), 0.0)
    a = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get("A", "N"), 0.0)

    # Scope
    s = metrics.get("S", "U")

    if s == "U":  # Unchanged
        impact = 6.42 * (c + i + a)
    else:  # Changed
        impact = 7.52 * (c + i + a - 0.029) - 3.25 * ((c + i + a - 0.02) ** 15)

    # Exploitability sub-score calculation
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics.get("AV", "N"), 0.85)
    ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC", "L"), 0.77)
    pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(metrics.get("PR", "N"), 0.85)
    ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI", "N"), 0.85)

    exploitability = 8.22 * av * ac * pr * ui

    # Base score
    if impact <= 0:
        return 0.0
    elif s == "U":  # Unchanged
        return min(10.0, round(impact + exploitability, 1))
    else:  # Changed
        return min(10.0, round(1.08 * (impact + exploitability), 1))


def _calculate_cvss_v4_base_score(metrics: dict) -> float:
    """Calculate CVSS v4 base score from metrics."""
    # Simplified CVSS v4 base score calculation
    # This is a basic implementation - CVSS v4 is more complex

    # For now, use a simplified approach similar to v3
    # In production, you'd want a proper CVSS v4 library
    return _calculate_cvss_v3_base_score(metrics)


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


def assess_vulns(findings: List[VulnScan]) -> List[VulnAssessment]:
    """
    Enrich detector findings with KEV/EPSS/risk and return VulnAssessment models.
    """
    results: List[VulnAssessment] = []

    for f in findings:
        cvss = _pick_cvss(f)
        cvss_norm = _normalize_cvss(cvss)

        # EPSS: use provided value if available, otherwise try to fetch; if fetch fails, assume 0
        epss = f.epss_score
        if epss is None:
            try:
                epss = fetch_epss(f.cve_id)  # expected 0..1
            except Exception:
                epss = 0.0

        kev = False
        try:
            kev = kev_contains(f.cve_id)
        except Exception:
            kev = False

        # Simple weighted risk: 60% impact (CVSS), 30% likelihood (EPSS), 10% KEV flag
        risk = (
            0.6 * cvss_norm
            + 0.3 * (float(epss) * 100.0)
            + 0.1 * (100.0 if kev else 0.0)
        )
        risk = round(risk, 1)
        label = _label_for_score(risk)

        rationale = (
            f"Impact(CVSS={cvss if cvss is not None else 'n/a'}), "
            f"Likelihood(EPSS={epss if epss is not None else 'n/a'}), "
            f"KEV={'yes' if kev else 'no'} → risk={risk} ({label})"
        )

        base = model_to_dict(f)  # works on Pydantic v1 & v2
        results.append(
            VulnAssessment(
                **base,
                kev=kev,
                risk_score=risk,
                risk_label=label,
                rationale=rationale,
            )
        )
    return results


# ---- DataFrame helpers -----------------------------------------------------


def assess_vulns_df(findings: List[VulnScan]) -> pd.DataFrame:
    """
    Run enrichment and return a tidy pandas DataFrame.
    """
    assessed = assess_vulns(findings)
    df = findings_to_df(assessed)
    # Optional: column order for readability
    cols = [
        "cve_id",
        "ghsa_id",
        "package_name",
        "package_version",
        "ecosystem",
        "language",
        "cvss_v4_score",
        "cvss_v3_score",
        "cvss_v2_score",
        "epss_score",
        "kev",
        "risk_score",
        "risk_label",
        "summary",
        "description",
        "references",
        "ghsa_url",
    ]
    df = df[[c for c in cols if c in df.columns]]
    return df


def assess_vulns_df_and_save(
    findings: List[VulnScan],
    out_dir: str = "artifacts/assessments",
) -> Tuple[pd.DataFrame, dict]:
    """
    Enrich → DataFrame → save CSV (+ Parquet if available). Return (df, paths).
    """
    df = assess_vulns_df(findings)
    paths = save_assessment_frames(df, out_dir=out_dir)
    return df, paths
