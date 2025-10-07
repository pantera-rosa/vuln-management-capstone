import asyncio
from typing import List, Optional
from schemas.models import VulnScan, VulnAssessment
from .providers import kev_contains, fetch_epss

W_IMPACT = 0.6
W_LIKE   = 0.3
W_KEV    = 0.1

def _best_cvss(v: VulnScan) -> Optional[float]:
    for s in (v.cvss_v4_score, v.cvss_v3_score, v.cvss_v2_score):
        if s is not None:
            return s
    return None

def _normalize_cvss(score: Optional[float]) -> float:
    if score is None:
        return 0.0
    return max(0.0, min(10.0, score)) / 10.0

def _risk_label(score_0_100: float) -> str:
    if score_0_100 >= 90: return "CRITICAL"
    if score_0_100 >= 70: return "HIGH"
    if score_0_100 >= 40: return "MEDIUM"
    if score_0_100 >  0:  return "LOW"
    return "NONE"

async def _assess_one(v: VulnScan) -> VulnAssessment:
    epss = v.epss_score
    if epss is None:
        epss, _ = await fetch_epss(v.cve_id)
    kev = await kev_contains(v.cve_id)

    impact = _normalize_cvss(_best_cvss(v))
    like   = float(epss or 0.0)
    boost  = 1.0 if kev else 0.0

    composite = (W_IMPACT * impact) + (W_LIKE * like) + (W_KEV * boost)
    risk_0_100 = round(100 * max(0.0, min(1.0, composite)), 1)
    label = _risk_label(risk_0_100)

    return VulnAssessment(
        **v.dict(),
        kev=kev,
        risk_score=risk_0_100,
        risk_label=label,
        rationale=(
            f"Impact(CVSS={_best_cvss(v) if _best_cvss(v) is not None else 'NA'}), "
            f"Likelihood(EPSS={epss if epss is not None else 'NA'}), "
            f"KEV={'yes' if kev else 'no'} → risk={risk_0_100} ({label})"
        )
    )

def assess_vulns(findings: List[VulnScan]) -> List[VulnAssessment]:
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        tasks = [_assess_one(VulnScan(**f.dict())) for f in findings]
        out = loop.run_until_complete(asyncio.gather(*tasks))
        return out
    finally:
        loop.close()
