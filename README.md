# VulnGuard — Vulnerability Management Library

Automated Detection, Assessment, and Remediation of Unfixed Software Vulnerabilities Using Machine Learning

## Quickstart

### Prerequisites

- Python 3.11+
- CLI tools: `syft` and `grype`
  - macOS (Homebrew):
    - `brew install anchore/syft/syft`
    - `brew install --cask grype`

### Setup & Usage (Poetry + Make)

```bash
pipx install poetry
make install
```

Completevulnerability management pipeline

```bash
make pipeline
```

Or run individual steps

```bash
make sbom    # Extract SBOM
make scan    # Run vulnerability scan
make assess  # Risk assessment with EPSS/KEV
```

### Inspect Results

**Scan Results (Parquet):**

```bash
python - <<'PY'
import pandas as pd
df=pd.read_parquet('test/resources/verademo_grype_scan_df.parquet')
print('shape=', df.shape)
print('columns=', list(df.columns))
print(df.head(5).to_string(index=False))
PY
```

**Risk Assessment Results (CSV/Parquet):**

```bash
# Assessment results saved to artifacts/assessments/
ls artifacts/assessments/
# assessment_YYYYMMDD-HHMMSS.csv
# assessment_YYYYMMDD-HHMMSS.parquet
```

**Key Output Columns:**

- **Scan**: `id`, `package_name`, `package_version`, `cvss_v2_score`, `cvss_v3_score`, `epss_score`, `summary`
- **Assessment**: `risk_score`, `risk_label`, `kev`, `rationale` (CRITICAL/HIGH/MEDIUM/LOW)

## Project Structure

```
src/backend/
├─ workflow/
│  ├─ vuln_detect/
│  │  └─ vuln_scan.py        # SBOM extraction & vulnerability scanning
│  ├─ vuln_assess/
│  │  └─ assessor.py         # Risk assessment & enrichment
│  └─ vuln_remediate/
│     └─ remediator.py       # Remediation recommendations
├─ schemas/
│  └─ schemas.py             # Pydantic models
├─ utils/
│  └─ compat.py              # Pydantic v1/v2 compatibility
└─ app/
   └─ main.py                # FastAPI application (optional)
```

## Features

### 🔍 **Vulnerability Detection**

- **SBOM Generation**: Extract software bill of materials with Syft
- **Vulnerability Scanning**: Find known vulnerabilities with Grype
- **Normalized Output**: Structured parquet/CSV with CVSS, EPSS, references

### 📊 **Risk Assessment**

- **Multi-factor Scoring**: CVSS (60%) + EPSS (30%) + KEV (10%)
- **External Intelligence**: EPSS exploitability + CISA KEV database
- **Risk Labels**: CRITICAL/HIGH/MEDIUM/LOW with rationale
- **Timestamps**: All outputs include creation timestamps

### 🔧 **Remediation Support**

- **Upgrade Recommendations**: Version suggestions for vulnerable packages
- **Code Analysis**: Automated fix generation (planned)

## Library Usage

```python
from src.backend.workflow.vuln_detect.vuln_scan import extract_sbom, perform_vuln_scan
from src.backend.workflow.vuln_assess.assessor import assess_vulns_df_and_save
from src.backend.schemas.models import VulnScan

# Complete vulnerability management workflow
extract_sbom('.', 'sbom.spdx.json')
df = perform_vuln_scan('sbom.spdx.json', 'results.parquet')

# Risk assessment with external intelligence
vulns = [VulnScan(**row) for row in df.to_dict('records')]
assessed_df, paths = assess_vulns_df_and_save(vulns, 'artifacts/assessments')

print(f"Found {len(df)} vulnerabilities")
print(f"Risk assessment saved to {paths}")
```
