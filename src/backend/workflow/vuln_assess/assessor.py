from __future__ import annotations
from typing import List, Tuple, Optional
import os, json, math
import pandas as pd
import numpy as np
from src.backend.utils.compat import model_to_dict
from src.backend.schemas.models import VulnScan, VulnAssessment
from src.backend.utils.df import findings_to_df, save_assessment_frames
from src.backend.workflow.vuln_assess.providers import kev_contains, fetch_epss

__all__ = ["assess_vulns", "assess_vulns_df", "assess_vulns_df_and_save"]

# ---- helpers ---------------------------------------------------------------


def _first_num(*vals) -> Optional[float]:
    for x in vals:
        if x is None:
            continue
        try:
            xf = float(x)
            if not math.isnan(xf):
                return xf
        except Exception:
            continue
    return None

def _pick_cvss(v: VulnScan) -> Optional[float]:
    """
    Prefer the newest numeric base score available: v4 -> v3 -> v2.
    Fall back to legacy *_score fields if they are numeric.
    """
    return _first_num(
        getattr(v, "cvss_v4_base_score", None),
        getattr(v, "cvss_v3_base_score", None),
        getattr(v, "cvss_v2_base_score", None),
        getattr(v, "cvss_v4_score", None),
        getattr(v, "cvss_v3_score", None),
        getattr(v, "cvss_v2_score", None),
    )


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
    Option 6 — Reachability-first
    risk = 0.5*EPSS% + 0.5*CVSS_base% + 15 if reachable
    """
    results: List[VulnAssessment] = []
    for f in findings:
        cvss = _first_num(
            getattr(f, "cvss_v4_base_score", None),
            getattr(f, "cvss_v3_base_score", None),
            getattr(f, "cvss_v2_base_score", None),
            _pick_cvss(f)
        )
        cvss_norm = _normalize_cvss(cvss)

        epss = getattr(f, "epss_score", None)
        if epss is None:
            try:
                epss = fetch_epss(f.cve_id)  # expected 0..1
            except Exception:
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


def assess_vulns_df(findings: List[VulnScan]) -> pd.DataFrame:
    """
    Run enrichment and return a tidy pandas DataFrame.
    """
    assessed = assess_vulns(findings)
    df = findings_to_df(assessed)
    # Optional: column order for readability
    cols = [
        "id",
        "related_id",
        "package_name",
        "package_version",
        "language",
        "related_vuln_datasource",
        "severity",
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
        "epss_score",
        "epss_percentile",
        "kev",
        "risk_score",
        "risk_label",
        "rationale",
        "summary",
        "description",
        "references",
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