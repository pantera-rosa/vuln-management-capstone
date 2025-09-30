from pydantic import BaseModel

class VulnScan(BaseModel):
    cve_id: str
    package_name: str
    package_version: str
    cvss_score: float | None
    cvss_version: int | None
    description: str
    epss_score: float | None
    references: list[str]