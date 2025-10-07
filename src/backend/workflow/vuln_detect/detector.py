from typing import List
from schemas.models import VulnScan  # ✅ absolute import

def detect_vulns(repo_url: str) -> List[VulnScan]:
    # Replace this stub with your actual detection.
    # Keeping a concrete example so the pipeline runs end-to-end.
    return [
        VulnScan(
            cve_id="CVE-2021-44228",
            ghsa_id="GHSA-jfh8-c2jp-5v3q",
            ghsa_url="https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
            language="Java",
            package_name="org.apache.logging.log4j:log4j-core",
            package_version="2.14.1",
            ecosystem="Maven",
            cvss_v2_score=10.0,
            cvss_v3_score=10.0,
            cvss_v4_score=10.0,
            epss_score=0.94,  # set a float to avoid network during local testing
            summary="Log4Shell in Apache Log4j",
            description="JNDI lookup in Log4j may allow remote code execution.",
            references=["https://logging.apache.org/log4j/2.x/security.html"],
        )
    ]
