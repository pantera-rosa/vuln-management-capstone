from typing import Optional, List
from pydantic import Field, AnyUrl
from .common import ApiModel, Language


class ExtractSbomInput(ApiModel):
    dir_path: str = Field(..., description="Directory to analyze")
    output_sbom_path: str = Field(..., regex=r".+\.spdx\.json$")


class VulnScanInput(ApiModel):
    sbom_path: str = Field(..., regex=r".+\.spdx\.json$")
    output_pd_path: str = Field(..., regex=r".+\.parquet$")


class VulnScanResultRow(ApiModel):
    id: Optional[str] = None
    related_id: Optional[str] = None
    related_vuln_datasource: Optional[str] = None
    language: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    fixed_version: Optional[str] = None
    cvss_v2_score: Optional[str] = None
    cvss_v2_version: Optional[str] = None
    cvss_v3_score: Optional[str] = None
    cvss_v3_version: Optional[str] = None
    cvss_v4_vector: Optional[str] = None
    cvss_v4_version: Optional[str] = None
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    epss_percentile: Optional[float] = Field(None, ge=0.0, le=1.0)
    summary: Optional[str] = None
    description: Optional[str] = None
    references: Optional[List[AnyUrl]] = None


class VulnScanResult(ApiModel):
    items: List[VulnScanResultRow]
    total: int = 0
