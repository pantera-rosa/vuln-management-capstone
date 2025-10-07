from __future__ import annotations
from functools import lru_cache
from typing import Optional
import httpx

# EPSS and KEV endpoints
_EPSS_API = "https://api.first.org/data/v1/epss?cve={cve}"
_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_epss(cve_id: str) -> float:
    """
    Synchronous EPSS fetcher.
    Returns a float in [0,1]. Falls back to 0.0 on any issue.
    """
    try:
        with httpx.Client(timeout=5.0) as client:
            r = client.get(_EPSS_API.format(cve=cve_id))
            r.raise_for_status()
            data = r.json()
        recs = data.get("data") or []
        if recs:
            return float(recs[0].get("epss", 0.0) or 0.0)
    except Exception:
        pass
    return 0.0

@lru_cache(maxsize=2048)
def kev_contains(cve_id: str) -> bool:
    """
    Synchronous KEV check. Cached to avoid re-downloading.
    """
    try:
        with httpx.Client(timeout=10.0) as client:
            r = client.get(_KEV_JSON)
            r.raise_for_status()
            data = r.json()
        for item in data.get("vulnerabilities", []):
            if item.get("cveID") == cve_id:
                return True
    except Exception:
        pass
    return False
