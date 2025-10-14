## Test Vuln Scan Locally
### 1. Python shell only
To test, clone your vulnerable test repo (e.g. `verademo`). 
Install `poetry` if not installed already:
```
curl -sSL https://install.python-poetry.org | python3 -
poetry install
```
Install `syft` and `grype` if not installed already:
```
curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
export PATH=/usr/local/bin:$PATH
```
Then, within the vuln-management-capstone` root directory, run `poetry run python3 -i` and within the Python shell, run (replace dir/file paths with whatever you want)
```
>>> from src.backend.workflow.vuln_detect.vuln_scan import extract_sbom, perform_vuln_scan
>>> extract_sbom("verademo", "verademo_sbom.spdx.json")
>>> df = perform_vuln_scan("verademo_sbom.spdx.json", "verademo_grype_scan.json", "verademo_grype_scan_df.parquet")
finished grype scan.
finished converting grype scan to pandas dataframe
finished saving grype scan pandas dataframe
>>> df
... shows pandas dataframe contents
>>> read_df = df.read_parquet("verademo_grype_scan_df.parquet")
>>> read_df
... shows pandas dataframe contents
```
### 2. Docker
You can test `perform_vuln_scan()` with Docker:
```
docker build -t vuln_scan -f src/backend/workflow/vuln_detect/Dockerfile.scan .
docker run -it vuln_scan /bin/bash
```
Within the bash shell, you can test `perform_vuln_scan()`. First, manually create the SBOM file:
```
apt update
apt install vim 
vim verademo_sbom.spdx.json (paste in the contents of SBOM file)
```
Then run `python3 -i` and within the Python shell run
```
>>> from vuln_scan import extract_sbom, perform_vuln_scan
>>> df = perform_vuln_scan("verademo_sbom.spdx.json", "verademo_grype_scan.json", "verademo_grype_scan_df.parquet")
.... same as above
```