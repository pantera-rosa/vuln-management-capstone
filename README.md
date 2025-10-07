mkdir -p src/backend
cat > src/backend/README.md <<'EOF'
# VulnGuard — CLI Vulnerability Workflow

End-to-end, local-first vulnerability pipeline you can run from the command line:

- **detect** vulnerable deps (stub/example provided)
- **assess** risk using **CVSS**/**EPSS** plus **CISA KEV** enrichment
- **export** results to **CSV** (always) and **Parquet** (if available)
- **remediate** with upgrade suggestions

The project is a simple Python CLI (no server). Commands are implemented with **Typer**.

---

## Quick start

```bash
# From repo root
cd src/backend

# Create & activate a venv (Python 3.10+)
python -m venv .venv
source .venv/bin/activate       # (Windows: .venv\Scripts\activate)

# Install deps
pip install -r requirements.txt

# Run the CLI
python cli.py --help

python cli.py pipeline \
  --repo-url https://github.com/example/repo \
  --out-dir artifacts

python cli.py detect \
  --repo-url https://github.com/example/repo \
  --out artifacts/detect/findings.json

python cli.py assess \
  --in artifacts/detect/sample_assess.json \
  --out-dir artifacts/assessments \
  --save

python cli.py remediate \
  --in artifacts/assessments/assessed.json \
  --out artifacts/remediations/recommendations.json

src/backend/
├─ cli.py                   # Typer-based CLI entrypoint
├─ schemas/
│  └─ models.py             # Pydantic models (VulnScan, VulnAssessment, Remediation, etc.)
├─ utils/
│  ├─ df.py                 # DataFrame helpers & CSV/Parquet writers
│  └─ compat.py             # model_to_dict() (Pydantic v1/v2 compatible)
└─ workflow/
   ├─ vuln_detect/
   │  └─ detector.py        # stubbed detector → List[VulnScan]
   ├─ vuln_assess/
   │  ├─ assessor.py        # risk enrichment + DataFrame helpers
   │  └─ providers.py       # EPSS/KEV providers (sync httpx.Client)
   └─ vuln_remediate/
      └─ remediator.py      # recommendations → List[Remediation]

# schemas/models.py
from pydantic import BaseModel
from typing import List, Optional

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

class VulnAssessment(VulnScan):
    kev: bool | None = None
    risk_score: float | None = None
    risk_label: str | None = None
    rationale: Optional[str] = None

class Remediation(BaseModel):
    cve_id: str
    package_name: str
    current_version: str
    recommendation: str
    references: List[str] = []

[
  {
    "cve_id": "CVE-2021-44228",
    "ghsa_id": "GHSA-jfh8-c2jp-5v3q",
    "ghsa_url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
    "language": "Java",
    "package_name": "org.apache.logging.log4j:log4j-core",
    "package_version": "2.14.1",
    "ecosystem": "Maven",
    "cvss_v2_score": 10,
    "cvss_v3_score": 10,
    "cvss_v4_score": 10,
    "epss_score": null,
    "summary": "Log4Shell in Apache Log4j",
    "description": "JNDI lookup in Log4j may allow remote code execution.",
    "references": ["https://logging.apache.org/log4j/2.x/security.html"]
  }
]

{ "findings": [ /* ...as above... */ ] }
