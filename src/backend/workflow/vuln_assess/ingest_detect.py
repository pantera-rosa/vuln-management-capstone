from __future__ import annotations

from typing import Iterable, List, Optional
import math
import pandas as pd

from schemas.models import VulnScan

# ---------- helpers ----------

def _first_str(*vals) -> Optional[str]:
    for v in vals:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None

def _as_list(val) -> list[str]:
    if isinstance(val, list):
        return [str(x) for x in val if x is not None]
    if isinstance(val, str):
        return [val]
    return []

def _id_parts(row: pd.Series) -> tuple[Optional[str], Optional[str]]:
    """
    Try to find CVE and GHSA IDs from either primary id or related_id.
    Grype often exposes the CVE in vulnerability.id and GHSA in relatedVulnerabilities.id,
    but either can appear in either place depending on the datasource. :contentReference[oaicite:0]{index=0}
    """
    cve = None
    ghsa = None
    for key in ("id", "related_id"):
        v = row.get(key)
        if isinstance(v, str):
            u = v.upper()
            if u.startswith("CVE-"):
                cve = v
            if u.startswith("GHSA-"):
                ghsa = v
    return cve, ghsa

def _ghsa_url(ghsa_id: Optional[str]) -> Optional[str]:
    # GitHub Advisory Database uses /advisories/GHSA-xxxx-xxxx-xxxx format. :contentReference[oaicite:1]{index=1}
    return f"https://github.com/advisories/{ghsa_id}" if ghsa_id else None

def _guess_ecosystem(language: Optional[str], package_name: Optional[str]) -> str:
    """
    Heuristic mapping (good enough for initial triage).
    """
    lang = (language or "").lower()
    name = (package_name or "")

    if lang in {"java", "jvm"} or ":" in name:
        return "Maven"
    if lang in {"python"}:
        return "PyPI"
    if lang in {"javascript", "typescript", "node"}:
        return "npm"
    if lang in {"go", "golang"}:
        return "Go"
    if lang in {"ruby"}:
        return "RubyGems"
    if lang in {"rust"}:
        return "crates.io"
    if lang in {"php"}:
        return "Packagist"
    return "Unknown"

def _maybe_cvss_from_vector(vector: Optional[str]) -> Optional[float]:
    """
    If we have a CVSS vector string (e.g., 'CVSS:3.1/AV:N/...'), try to compute a base score
    using the 'cvss' Python package. If it's not installed, return None. :contentReference[oaicite:2]{index=2}
    """
    if not isinstance(vector, str) or "/" not in vector:
        return None
    try:
        import cvss  # pip install cvss
        vec = vector.strip()
        if vec.startswith("CVSS:3"):
            return float(cvss.CVSS3(vec).scores()[0])  # base score
        if vec.startswith("CVSS:4"):
            # Library advertises v4 utilities; base score API may evolve. Try best effort. :contentReference[oaicite:3]{index=3}
            try:
                return float(cvss.CVSS4(vec).scores()[0])
            except Exception:
                return None
        # Fallback: assume v2 if it looks like a v2 vector (no 'CVSS:' prefix)
        if ":" not in vec and "/" in vec:
            return float(cvss.CVSS2(vec).scores()[0])
    except Exception:
        pass
    return None

def _coerce_cvss_numeric(row: pd.Series, which: str) -> Optional[float]:
    """
    Accept either:
      - a true numeric score column (e.g., 'cvss_v3_score' == 9.8), or
      - a vector column (e.g., 'cvss_v3_vector' or mislabeled 'cvss_v3_score' that actually holds 'CVSS:3.x/...').
    """
    num = row.get(f"cvss_{which}_score")
    vec = row.get(f"cvss_{which}_vector")

    # If score already numeric
    try:
        if num is not None and not (isinstance(num, float) and math.isnan(num)):
            # Might be a string with 'CVSS:3.1/...'; detect that case
            if isinstance(num, str) and "/" in num:
                return _maybe_cvss_from_vector(num)
            return float(num)
    except Exception:
        pass

    # Else try vector
    if isinstance(vec, str) and "/" in vec:
        return _maybe_cvss_from_vector(vec)

    # Some Grype templates put vectors into the *score* key by mistake; handle that. :contentReference[oaicite:4]{index=4}
    if isinstance(num, str) and "/" in num:
        return _maybe_cvss_from_vector(num)

    return None

# ---------- main bridge ----------

def grype_df_to_vulnscan(df: pd.DataFrame) -> List[VulnScan]:
    """
    Convert the DataFrame emitted by vuln_detect.vuln_scan.perform_vuln_scan()
    into a list[VulnScan] that the assessor understands.
    """
    items: List[VulnScan] = []
    for _, row in df.iterrows():
        cve_id, ghsa_id = _id_parts(row)

        # CVSS (try v3 first, then v4, then v2)
        cvss_v3 = _coerce_cvss_numeric(row, "v3")
        cvss_v4 = _coerce_cvss_numeric(row, "v4")
        cvss_v2 = _coerce_cvss_numeric(row, "v2")

        # EPSS (may already be present from Grype)
        epss_score = None
        try:
            epss_val = row.get("epss_score")
            if epss_val is not None and not (isinstance(epss_val, float) and math.isnan(epss_val)):
                epss_score = float(epss_val)
        except Exception:
            epss_score = None

        language = row.get("language")
        package_name = row.get("package_name")
        package_version = row.get("package_version")
        ecosystem = _guess_ecosystem(language, package_name)

        summary = _first_str(row.get("summary"), row.get("description"))
        description = _first_str(row.get("description"), row.get("summary"))
        references = _as_list(row.get("references"))

        items.append(
            VulnScan(
                cve_id=cve_id or "",
                ghsa_id=ghsa_id or "",
                ghsa_url=_ghsa_url(ghsa_id) or "",
                language=str(language or ""),
                package_name=str(package_name or ""),
                package_version=str(package_version or ""),
                ecosystem=ecosystem,
                cvss_v2_score=cvss_v2,
                cvss_v3_score=cvss_v3,
                cvss_v4_score=cvss_v4,
                epss_score=epss_score,
                summary=summary or "",
                description=description or "",
                references=references,
            )
        )
    return items

def load_grype_parquet_to_vulnscan(parquet_path: str) -> List[VulnScan]:
    """
    Read the parquet saved by perform_vuln_scan(...), then map into VulnScan models.
    """
    df = pd.read_parquet(parquet_path)
    return grype_df_to_vulnscan(df)
