.PHONY: install sbom scan clean lint test

install:
	poetry install

clone-log4j:
	@if [ ! -d "log4j" ]; then \
		echo "Cloning log4j repository..."; \
		git clone https://github.com/apache/logging-log4j1.git log4j; \
	else \
		echo "Log4j already exists, updating..."; \
		cd log4j && git pull; \
	fi

sbom: clone-log4j
	poetry run python -c "from src.backend.workflow.vuln_detect.vuln_scan import extract_sbom; extract_sbom('log4j', 'artifacts/detect/log4j_sbom.spdx.json')"

scan:
	poetry run python -c "from src.backend.workflow.vuln_detect.vuln_scan import perform_vuln_scan; perform_vuln_scan('artifacts/detect/log4j_sbom.spdx.json', output_scan_path='artifacts/detect/log4j_grype_scan.json', output_pd_path='artifacts/detect/log4j_grype_scan_df.parquet')"

detect:
	poetry run python -m src.backend.workflow.vuln_detect.detector --repo_url=https://github.com/apache/logging-log4j1.git --dir_path=artifacts/detect/repos/log4j --sbom_path=artifacts/detect/log4j_sbom.spdx.json --output_raw_scan_path=artifacts/detect/log4j_grype_scan.json --output_final_scan_path=artifacts/detect/log4j_grype_scan_df.parquet --display

identify:
	poetry run python -m src.backend.workflow.vuln_identify.identifier --vuln_scan_results_path=artifacts/detect/log4j_grype_scan_df.parquet --dep_repos_root_dir_path=artifacts/identify/repos --output_raw_scans_dir_path=artifacts/identify/semgrep_scans --output_final_scans_dir_path=artifacts/identify/semgrep_scans --output_pd_path=artifacts/identify/log4j_semgrep_results_df.parquet --display

assess:
	poetry run python -m src.backend.workflow.vuln_assess.assessor --vuln_identify_results_path=artifacts/identify/log4j_semgrep_results_df.parquet --output_dir=artifacts/assessments --display

remediate:
	poetry run python -m src.backend.workflow.vuln_remediate.remediator --vuln_results_path=$(shell ls -t artifacts/assessments/*.parquet | head -n 1) --dep_repos_root_dir_path=artifacts/identify/repos --model_id=01-ai/Yi-Coder-1.5B-Chat --output_pd_path=artifacts/remediate/log4j_remediate_pd.json --display

remediate-sagemaker:
	poetry run python -m src.backend.workflow.vuln_remediate.remediator --vuln_results_path=$(shell ls -t artifacts/assessments/*.parquet | head -n 1) --dep_repos_root_dir_path=artifacts/identify/repos --model_id=01-ai/Yi-Coder-1.5B-Chat --output_pd_path=artifacts/remediate/log4j_remediate_pd.json --use_sagemaker --sagemaker_endpoint_name=jumpstart-dft-hf-llm-mixtral-8x7b-20251125-220151 --aws_region=us-east-1 --display

pipeline: detect identify assess remediate

inspect:
	poetry run python -c "import pandas as pd; df=pd.read_parquet('artifacts/detect/log4j_grype_scan_df.parquet'); print('detect results shape=', df.shape); print('detect results columns=', list(df.columns)); print(df.head(5).to_string(index=False)); df=pd.read_parquet('artifacts/identify/semgrep_results_df.parquet'); print('identify results shape=', df.shape); print('identify results columns=', list(df.columns)); print(df.head(5).to_string(index=False))"

clean:
	rm -rf artifacts/*
	rm -rf docker_artifacts/*
	rm -rf log4j
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