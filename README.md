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

```
