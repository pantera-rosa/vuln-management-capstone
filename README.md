# VulnGuard — Vulnerability Management Library

Automated Detection, Identification, Assessment, and Remediation of Unfixed Software Vulnerabilities Using Machine Learning

### Prerequisites

- Python 3.11+
- Poetry: `pipx install poetry`
- CLI tools: `syft`, `grype`, `gh`, `semgrep`
  - macOS (Homebrew):
    - `brew install anchore/syft/syft`
    - `brew install --cask grype`
      `brew install gh`
      `python3 -m pip install semgrep`

### Configuration
Setup the following in your `.env` file:
```
GITHUB_ORG_NAME=...(name of GitHub org, defaults to Vuln-Guard)
GITHUB_PERSONAL_ACCESS_TOKEN=github_pat_...(GitHub PAT w/ no permissions)
GH_TOKEN=github_pat_...(GitHub org PAT w/ Read access to metadata, Read and Write access to administration)
SEMGREP_APP_TOKEN=...(Semgrep CLI token)
HF_TOKEN=hf_...(Hugging Face token)
```
Where to generate these tokens:
- Github: https://github.com/settings/personal-access-tokens
- Semgrep: https://semgrep.dev/orgs/vuln_guard/settings/tokens/cli
- Hugging Face: https://huggingface.co/settings/tokens

### Setup & Usage (Poetry + Make)

```bash
poetry lock
make install
```

**Complete vulnerability management pipeline:**

```bash
make pipeline
```

**Individual steps:**

```bash
make clone-verademo  # Clone VeraDemo (deliberately vulnerable Java app)
make sbom            # Extract SBOM from VeraDemo
make scan            # Run vulnerability scan
make detect          # alternative to make sbom -> make scan
make identify        # Run vulnerable code identification
make assess          # Risk assessment with EPSS/KEV
make remediate       # Run vulnerable code remediation
```

**Note:** This scans [VeraDemo](https://github.com/veracode/verademo) - a deliberately vulnerable Java web application designed for security testing.

### Inspect Results

**Scan Results (Parquet):**

```bash
make inspect
```

**Risk Assessment Results (CSV/Parquet):**

```bash
# Assessment results saved to artifacts/assessments/
ls artifacts/assessments/
# assessment_YYYYMMDD-HHMMSS.csv
# assessment_YYYYMMDD-HHMMSS.parquet
```

**Key Output Columns:**

- **Scan**: `cve_id`, `ghsa_id`, `package_name`, `package_version`, `fixed_version`, `cvss_v2_score`, `cvss_v3_score`, `epss_score`, `summary`, `description`, `cwe_id`
- **Identify**: `cwe_id`, `path`, `start_line`, `start_col`, `start_offset`, `end_line`, `end_col`, `end_offset`, `extra_lines`, `extra_dataflow_trace_taint_source`, `extra_dataflow_trace_intermediate_vars`, `extra_dataflow_trace_taint_sink`
- **Assessment**: `risk_score`, `risk_label`, `kev`, `rationale` (CRITICAL/HIGH/MEDIUM/LOW)
- **Remediation**: `recommendation`, `remediation_github_url`

## Project Structure

```
src/backend/
├─ workflow/
│  ├─ vuln_detect/
│  │  └─ detector.py         # SBOM extraction & vulnerability scanning
│  ├─ vuln_identify/
│  │  └─ identifier.py       # vulnerable code path identification
│  ├─ vuln_assess/
│  │  └─ assessor.py         # Risk assessment & enrichment
│  └─ vuln_remediate/
│     └─ remediator.py       # Remediation recommendations
├─ schemas/
│  └─ models.py              # Pydantic models
├─ utils/
│  ├─ compat.py              # Pydantic v1/v2 compatibility
|  ├─ cmd.py                 # running CLI commands
|  ├─ df.py                  # pandas dataframe compatability
|  ├─ http.py                # making http requests
|  └─ llm.py                 # loading and invoking LLMs
└─ app/
   └─ main.py                # FastAPI application (optional)
```

## Features

### 🔍 **Vulnerability Detection**

- **SBOM Generation**: Extract software bill of materials with Syft
- **Vulnerability Scanning**: Find known vulnerabilities with Grype
- **Normalized Output**: Structured parquet/CSV with CVSS, EPSS, references

### 📌 **Vulnerable Code Identification**
- **SAST Scanning**: Find vulnerable code patterns with Semgrep scan

### 📊 **Risk Assessment**

- **Multi-factor Scoring**: CVSS (60%) + EPSS (30%) + KEV (10%)
- **External Intelligence**: EPSS exploitability + CISA KEV database
- **Risk Labels**: CRITICAL/HIGH/MEDIUM/LOW with rationale
- **Timestamps**: All outputs include creation timestamps

### 🔧 **Remediation Support**

- **Upgrade Recommendations**: Version suggestions for vulnerable packages
- **Code Patching**: Automated code fix generation

## Library Usage
Replace arguments with appropriate values.

```python
from src.backend.workflow.vuln_detect.vuln_scan import extract_sbom, perform_vuln_scan
from src.backend.workflow.vuln_identify.vuln_code_identify import vuln_code_identify
from src.backend.workflow.vuln_assess.assessor import assess_vulns_df_and_save
from src.backend.worklfow.vuln_remediate.generate_remediation import generate_remediation
from src.backend.schemas.models import VulnCodeIdentification

# Scan VeraDemo (deliberately vulnerable Java app)
extract_sbom('verademo', 'sbom.spdx.json')
df = perform_vuln_scan('sbom.spdx.json', 'scan.json', 'results.parquet')

# Identify vulnerable code paths in unfixed open source dependencies
df = vuln_code_identify(df, 'repos', 'scans', 'scans', 'results.parquet')

# Risk assessment with external intelligence
vulns = [VulnCodeIdentification(**row) for row in df.to_dict('records')]
assessed_df, paths = assess_vulns_df_and_save(vulns, 'assessments')

print(f"Found {len(df)} vulnerabilities")
print(f"Risk assessment saved to {paths}")

# Remediation
remediated_df = generate_remediation(assessed_df, '01-ai/Yi-Coder-1.5B-Chat', 'remediations.json', 'repos', True)
print(f"remediations: {remediated_df}")
```
