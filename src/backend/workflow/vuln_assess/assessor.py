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
    # Try cvss_v2_score first (it's a float), then cvss_v4_vector (string), then cvss_v3_score (string)
    if v.cvss_v2_score is not None:
        return float(v.cvss_v2_score)
    # For now, return None for string CVSS vectors - in a real implementation you'd parse them
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
