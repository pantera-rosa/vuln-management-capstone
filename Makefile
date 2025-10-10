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
	poetry run python -c "from src.backend.workflow.vuln_detect.vuln_scan import extract_sbom; extract_sbom('verademo', 'test/resources/scan/verademo_sbom.spdx.json')"

scan:
	poetry run python -c "from src.backend.workflow.vuln_detect.vuln_scan import perform_vuln_scan; perform_vuln_scan('test/resources/scan/verademo_sbom.spdx.json', output_scan_path='test/resources/scan/verademo_grype_scan.json', output_pd_path='test/resources/scan/verademo_grype_scan_df.parquet')"

assess:
	poetry run python -c "from src.backend.workflow.vuln_assess.assessor import assess_vulns_df_and_save; from src.backend.schemas.models import VulnScan; import pandas as pd; import numpy as np; df=pd.read_parquet('test/resources/scan/verademo_grype_scan_df.parquet'); df=df.replace({np.nan: None}); vulns=[VulnScan(**row) for row in df.to_dict('records')]; assess_vulns_df_and_save(vulns, 'test/resources/assessments')"

pipeline: sbom scan assess

inspect:
	poetry run python -c "import pandas as pd; df=pd.read_parquet('test/resources/scan/verademo_grype_scan_df.parquet'); print('shape=', df.shape); print('columns=', list(df.columns)); print(df.head(5).to_string(index=False))"

clean:
	rm -rf test/resources/scan/*
	rm -rf test/resources/assessments/*
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
