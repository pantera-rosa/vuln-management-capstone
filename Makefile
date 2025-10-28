.PHONY: install sbom scan clean lint test

install:
	poetry install

clone-verademo:
	@if [ ! -d "verademo" ]; then \
		echo "Cloning VeraDemo repository..."; \
		git clone https://github.com/veracode/verademo.git verademo; \
	else \
		echo "VeraDemo already exists, updating..."; \
		cd verademo && git pull; \
	fi

sbom: clone-verademo
	poetry run python -c "from src.backend.workflow.vuln_detect.vuln_scan import extract_sbom; extract_sbom('verademo', 'artifacts/detect/verademo_sbom.spdx.json')"

scan:
	poetry run python -c "from src.backend.workflow.vuln_detect.vuln_scan import perform_vuln_scan; perform_vuln_scan('artifacts/detect/verademo_sbom.spdx.json', output_scan_path='artifacts/detect/verademo_grype_scan.json', output_pd_path='artifacts/detect/verademo_grype_scan_df.parquet')"

detect:
	poetry run python -c "from src.backend.workflow.vuln_detect.detector import detect_vulns; detect_vulns('https://github.com/veracode/verademo.git', 'artifacts/detect/repos/verademo', 'artifacts/detect/verademo_sbom.spdx.json', 'artifacts/detect/verademo_grype_scan.json', 'artifacts/detect/verademo_grype_scan_df.parquet')"

identify:
	poetry run python -c "from src.backend.workflow.vuln_identify.identifier import identify_vulns; from src.backend.schemas.models import VulnScan; import pandas as pd; import numpy as np; df=pd.read_parquet('artifacts/detect/verademo_grype_scan_df.parquet'); df=df.replace({np.nan: None}); vulns=[VulnScan(**row) for row in df.to_dict('records')]; identify_vulns(vulns, 'artifacts/identify/repos', 'artifacts/identify/semgrep_scans', 'artifacts/identify/semgrep_scans', 'artifacts/identify/semgrep_results_df.parquet')"

assess:
	poetry run python -c "from src.backend.workflow.vuln_assess.assessor import assess_vulns_df_and_save; from src.backend.schemas.models import VulnCodeIdentification; import pandas as pd; import numpy as np; df=pd.read_parquet('artifacts/identify/semgrep_results_df.parquet'); df=df.replace({np.nan: None}); vulns=[VulnCodeIdentification(**row) for row in df.to_dict('records')]; assess_vulns_df_and_save(vulns, 'artifacts/assessments')"

pipeline: detect identify assess

inspect:
	poetry run python -c "import pandas as pd; df=pd.read_parquet('artifacts/detect/verademo_grype_scan_df.parquet'); print('detect results shape=', df.shape); print('detect results columns=', list(df.columns)); print(df.head(5).to_string(index=False)); df=pd.read_parquet('artifacts/identify/semgrep_results_df.parquet'); print('identify results shape=', df.shape); print('identify results columns=', list(df.columns)); print(df.head(5).to_string(index=False))"

clean:
	rm -rf artifacts/*
	rm -rf docker_artifacts/*
	rm -rf verademo
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
