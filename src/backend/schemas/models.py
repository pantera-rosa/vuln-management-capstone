from typing import List, Optional
from pydantic import BaseModel
from typing import Dict


# 👇 This is the detector output you provided
class VulnScan(BaseModel):
    cve_id: str  # CVE ID
    ghsa_id: str  # GHSA ID
    severity: Optional[str] = None
    related_vuln_datasource: str
    language: str
    package_name: str
    package_version: str
    fixed_version: Optional[str] = None
    cvss_v2_score: Optional[str] = None
    cvss_v2_version: Optional[str] = None
    cvss_v2_base_score: Optional[float] = None
    cvss_v2_exploitability_score: Optional[float] = None
    cvss_v2_impact_score: Optional[float] = None
    cvss_v3_score: Optional[str] = None 
    cvss_v3_version: Optional[str] = None
    cvss_v3_base_score: Optional[float] = None
    cvss_v3_exploitability_score: Optional[float] = None
    cvss_v3_impact_score: Optional[float] = None
    cvss_v4_score: Optional[str] = None
    cvss_v4_version: Optional[str] = None
    cvss_v4_base_score: Optional[float] = None
    cvss_v4_exploitability_score: Optional[float] = None
    cvss_v4_impact_score: Optional[float] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    summary: str
    description: str
    references: List[str]
    source_code_location: Optional[str] = None
    cwe_id: Optional[str] = None
    cwe_name: Optional[str] = None

class VulnCodeIdentification(VulnScan):
    path: Optional[str] = None,
    start_line: Optional[float] = None,
    start_col:  Optional[float] = None,
    start_offset: Optional[float] = None,
    end_line: Optional[float] = None,
    end_col: Optional[float] = None,
    end_offset: Optional[float] = None,
    extra_message: Optional[str] = None,
    extra_metadata_likelihood: Optional[str] = None,
    extra_metadata_impact: Optional[str] = None,
    extra_metadata_confidence: Optional[str] = None,
    extra_metadata_vulnerability_class: Optional[str] = None,
    extra_severity: Optional[str] = None,
    extra_lines: Optional[str] = None,
    extra_validation_state: Optional[str] = None,
    extra_dataflow_trace_taint_source: Optional[str] = None,
    extra_dataflow_trace_intermediate_vars: Optional[str] = None,
    extra_dataflow_trace_taint_sink: Optional[str] = None,
    extra_fix: Optional[str] = None,
    filename: Optional[str] = None

# 👇 Enriched result returned by assessment
class VulnAssessment(VulnCodeIdentification):
    kev: bool | None = None
    risk_score: float | None = None
    risk_label: str | None = None
    rationale: Optional[str] = None


# 👇 Remediation items returned by the remediate step
class Remediation(BaseModel):
    cve_id: str
    package_name: str
    package_version: str
    recommendation: str
    remediation_github_url: Optional[str] = None


class AssessRequest(BaseModel):
    findings: List[VulnScan]


class AssessResponse(BaseModel):
    repo_url: Optional[str] = None
    findings: List[VulnAssessment]
    artifacts: Optional[Dict[str, str]] = None
