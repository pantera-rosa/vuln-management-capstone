from typing import List, Optional
from pydantic import BaseModel
from typing import Dict


# 👇 This is the detector output you provided
class VulnScan(BaseModel):
    id: str  # GHSA ID
    related_id: str  # CVE ID
    related_vuln_datasource: str
    language: str
    package_name: str
    package_version: str
    fixed_version: Optional[str] = None
    cvss_v2_score: Optional[float] = None
    cvss_v2_version: Optional[str] = None
    cvss_v3_score: Optional[str] = None  # CVSS vector string
    cvss_v3_version: Optional[str] = None
    cvss_v4_vector: Optional[str] = None
    cvss_v4_version: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    summary: str
    description: str
    references: List[str]


# 👇 Enriched result returned by assessment
class VulnAssessment(VulnScan):
    kev: bool | None = None
    risk_score: float | None = None
    risk_label: str | None = None
    rationale: Optional[str] = None


# 👇 Remediation items returned by the remediate step
class Remediation(BaseModel):
    cve_id: str
    package_name: str
    current_version: str
    recommendation: str
    references: List[str] = []


class AssessRequest(BaseModel):
    findings: List[VulnScan]


class AssessResponse(BaseModel):
    repo_url: Optional[str] = None
    findings: List[VulnAssessment]
    artifacts: Optional[Dict[str, str]] = None
