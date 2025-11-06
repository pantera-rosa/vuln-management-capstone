# src/backend/workflow/vuln_assess/providers.py
from __future__ import annotations
import os, time, json
from typing import Optional, Set
import requests
import numpy as np

# --- EPSS --------------------------------------------------------------------
_EPSS_URL = "https://api.first.org/data/v1/epss"  # returns probability + percentile
# EPSS score is a probability in [0,1]; higher means more likely exploitation.  :contentReference[oaicite:4]{index=4}

# A tiny HTTP helper with retries + timeouts (good for Lambda)
_SESSION = requests.Session()
_ADAPTER = requests.adapters.HTTPAdapter(max_retries=3)
_SESSION.mount("https://", _ADAPTER)
_TIMEOUT = float(os.getenv("HTTP_TIMEOUT_SEC", "21600"))  # 21.6s by default

def fetch_epss(cve_id: str) -> Optional[float]:
    """
    Return EPSS probability (0..1) for a CVE, or np.nan if unavailable.
    Uses FIRST EPSS API: https://api.first.org/data/v1/epss?cve=<CVE>  :contentReference[oaicite:5]{index=5}
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return np.nan
    try:
        r = _SESSION.get(_EPSS_URL, params={"cve": cve_id}, timeout=_TIMEOUT)
        r.raise_for_status()
        data = r.json().get("data") or []
        if not data:
            return np.nan
        # API returns strings; convert to float
        epss_str = data[0].get("epss")
        if epss_str is None:
            return np.nan
        return float(epss_str)
    except Exception:
        return np.nan  # caller differentiates np.nan from legit 0.0


# --- KEV ---------------------------------------------------------------------
# CISA KEV JSON feed (default URL)  :contentReference[oaicite:6]{index=6}
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_KEV_CACHE: Set[str] = set()
_KEV_LAST_FETCH = 0.0
_KEV_TTL_SEC = int(os.getenv("KEV_TTL_SEC", "21600"))  # 6h by default

def _refresh_kev_if_needed():
    global _KEV_LAST_FETCH, _KEV_CACHE
    now = time.time()
    if (now - _KEV_LAST_FETCH) < _KEV_TTL_SEC and _KEV_CACHE:
        return
    try:
        r = _SESSION.get(_KEV_URL, timeout=_TIMEOUT)
        r.raise_for_status()
        payload = r.json()
        vulns = payload.get("vulnerabilities") or []
        _KEV_CACHE = { (v.get("cveID") or "").strip() for v in vulns if v.get("cveID") }
        _KEV_LAST_FETCH = now
    except Exception:
        # Keep old cache if refresh fails
        pass

def kev_contains(cve_id: str) -> bool:
    """
    True if cve_id appears in the CISA KEV catalog (JSON feed).
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return False
    _refresh_kev_if_needed()
    return cve_id in _KEV_CACHE
