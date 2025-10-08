.PHONY: install sbom scan lint fmt

install:
	poetry install

sbom:
	poetry run python -c "from src.backend.workflow.vuln_detect.vuln_scan import extract_sbom; extract_sbom('.', 'test/resources/verademo_sbom.spdx.json')"

scan:
	poetry run python -c "from src.backend.workflow.vuln_detect.vuln_scan import perform_vuln_scan; perform_vuln_scan('test/resources/verademo_sbom.spdx.json', 'test/resources/verademo_grype_scan_df.parquet')"


