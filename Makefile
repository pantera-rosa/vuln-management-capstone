.PHONY: install sbom scan clean lint test

# Variables
# input github repo url
GITHUB_REPO_URL := https://github.com/apache/logging-log4j1
# directory to clone github repo into
GITHUB_REPO_NAME := log4j
# prefix for artifact files
ARTIFACT_PREFIX := log4j

install:
	poetry install

clone:
	@if [ ! -d "$(GITHUB_REPO_NAME)" ]; then \
		echo "Cloning $(GITHUB_REPO_NAME) repository..."; \
		git clone $(GITHUB_REPO_URL) $(GITHUB_REPO_NAME); \
	else \
		echo "$(GITHUB_REPO_NAME) already exists, updating..."; \
		cd $(GITHUB_REPO_NAME) && git pull; \
	fi

sbom: clone
	poetry run python -c "from src.backend.workflow.vuln_detect.vuln_scan import extract_sbom; extract_sbom('$(GITHUB_REPO_NAME)', 'artifacts/detect/$(ARTIFACT_PREFIX)_sbom.spdx.json')"

scan:
	poetry run python -c "from src.backend.workflow.vuln_detect.vuln_scan import perform_vuln_scan; perform_vuln_scan('artifacts/detect/$(ARTIFACT_PREFIX)_sbom.spdx.json', output_scan_path='artifacts/detect/$(ARTIFACT_PREFIX)_grype_scan.json', output_pd_path='artifacts/detect/$(ARTIFACT_PREFIX)_grype_scan_df.parquet')"

detect:
	poetry run python -m src.backend.workflow.vuln_detect.detector --repo_url=$(GITHUB_REPO_URL) --dir_path=artifacts/detect/repos/$(GIHUB_REPO_NAME) --sbom_path=artifacts/detect/$(ARTIFACT_PREFIX)_sbom.spdx.json --output_raw_scan_path=artifacts/detect/$(ARTIFACT_PREFIX)_grype_scan.json --output_final_scan_path=artifacts/detect/$(ARTIFACT_PREFIX)_grype_scan_df.parquet --display

identify:
	poetry run python -m src.backend.workflow.vuln_identify.identifier --vuln_scan_results_path=artifacts/detect/$(ARTIFACT_PREFIX)_grype_scan_df.parquet --dep_repos_root_dir_path=artifacts/identify/repos --output_raw_scans_dir_path=artifacts/identify/semgrep_scans --output_final_scans_dir_path=artifacts/identify/semgrep_scans --output_pd_path=artifacts/identify/$(ARTIFACT_PREFIX)_semgrep_results_df.parquet --display

assess:
	poetry run python -m src.backend.workflow.vuln_assess.assessor --vuln_identify_results_path=artifacts/identify/$(ARTIFACT_PREFIX)_semgrep_results_df.parquet --output_dir=artifacts/assessments --display

remediate:
	poetry run python -m src.backend.workflow.vuln_remediate.remediator --vuln_results_path=$(shell ls -t artifacts/assessments/*.parquet | head -n 1) --dep_repos_root_dir_path=artifacts/identify/repos --model_id=01-ai/Yi-Coder-1.5B-Chat --output_pd_path=artifacts/remediate/$(ARTIFACT_PREFIX)_remediate_pd.json --display

remediate-sagemaker:
	poetry run python -m src.backend.workflow.vuln_remediate.remediator --vuln_results_path=$(shell ls -t artifacts/assessments/*.parquet | head -n 1) --dep_repos_root_dir_path=artifacts/identify/repos --model_id=01-ai/Yi-Coder-1.5B-Chat --output_pd_path=artifacts/remediate/$(ARTIFACT_PREFIX)_remediate_pd.json --use_sagemaker --sagemaker_endpoint_name=jumpstart-dft-hf-llm-mixtral-8x7b-20251125-220151 --aws_region=us-east-1 --display

pipeline: detect identify assess remediate

inspect:
	poetry run python -c "import pandas as pd; df=pd.read_parquet('artifacts/detect/$(ARTIFACT_PREFIX)_grype_scan_df.parquet'); print('detect results shape=', df.shape); print('detect results columns=', list(df.columns)); print(df.head(5).to_string(index=False)); df=pd.read_parquet('artifacts/identify/$(ARTIFACT_PREFIX)_semgrep_results_df.parquet'); print('identify results shape=', df.shape); print('identify results columns=', list(df.columns)); print(df.head(5).to_string(index=False))"

clean:
	rm -rf artifacts/*
	rm -rf docker_artifacts/*
	rm -rf $(GITHUB_REPO_NAME)
	rm -rf __pycache__ src/backend/__pycache__ src/backend/workflow/__pycache__

lint:
	poetry run python -m flake8 src/backend/
	poetry run python -m black --check src/backend/

test:
	poetry run python -m pytest test/ -v

# Development helpers
dev-install:
	poetry install --with dev

format:
	poetry run python -m black src/backend/
	poetry run python -m isort src/backend/