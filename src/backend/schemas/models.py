from typing import List, Optional
from pydantic import BaseModel

# 👇 This is the detector output you provided
class VulnScan(BaseModel):
    cve_id: str
    ghsa_id: str
    ghsa_url: str
    language: str
    package_name: str
    package_version: str
    ecosystem: str
    cvss_v2_score: float | None
    cvss_v3_score: float | None
    cvss_v4_score: float | None
    epss_score: float | None
    summary: str
    description: str
    references: list[str]

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
