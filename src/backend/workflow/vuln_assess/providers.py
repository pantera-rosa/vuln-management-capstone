import os, datetime as dt
from typing import Optional, Tuple
from utils.http import get_json

EPSS_BASE = "https://api.first.org/data/v1/epss"
KEV_URL   = os.getenv(
    "KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

_kev_cache: set[str] = set()
_kev_loaded_at: Optional[dt.datetime] = None

async def kev_contains(cve_id: str) -> bool:
    global _kev_cache, _kev_loaded_at
    now = dt.datetime.utcnow()
    if not _kev_loaded_at or (now - _kev_loaded_at).seconds > 3600:
        data = await get_json(KEV_URL, params=None)
        items = (data or {}).get("vulnerabilities") or (data or {}).get("known_exploited_vulnerabilities") or []
        _kev_cache = {item.get("cveID") or item.get("cveId") for item in items if item.get("cveID") or item.get("cveId")}
        _kev_loaded_at = now
    return cve_id in _kev_cache

async def fetch_epss(cve_id: str):
    data = await get_json(EPSS_BASE, params={"cve": cve_id})
    recs = (data or {}).get("data") or []
    if not recs:
        return None, None
    rec = recs[0]
    epss = float(rec.get("epss")) if rec.get("epss") is not None else None
    pct = float(rec.get("percentile")) if rec.get("percentile") is not None else None
    return epss, pct
