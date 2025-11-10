from typing import List, Union
from src.backend.schemas.models import VulnScan, VulnCodeIdentification, VulnAssessment, Remediation  # ✅ absolute

AnyFinding = Union[VulnAssessment, VulnScan, VulnCodeIdentification]

def remediate_vulns(items: List[AnyFinding]) -> List[Remediation]:
    recs: List[Remediation] = []
    for it in items:
        pkg = it.package_name
        current = it.package_version
        if it.cve_id == "CVE-2021-44228" and "log4j-core" in pkg:
            recommendation = (
                "Upgrade log4j-core to 2.17.1+ (JDK8+) or 2.12.4 (JDK7). "
                "Remove JndiLookup from older JARs only as a temporary mitigation."
            )
            refs = [
                "https://logging.apache.org/log4j/2.x/security.html",
                "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
            ]
        else:
            recommendation = f"Upgrade {pkg} to a vendor-recommended non-vulnerable version."
            refs = list(getattr(it, "references", []))

        recs.append(
            Remediation(
                cve_id=it.cve_id,
                package_name=pkg,
                current_version=current,
                recommendation=recommendation,
                references=refs,
            )
        )
    return recs
