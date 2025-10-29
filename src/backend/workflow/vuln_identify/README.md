# Vulnerability Code Identification
Contains scripts and Dockerfiles needed for vulnerability code identification. For other methods of testing locally with Poetry + Make or library usage, see root README.md. Run all of the following from the root directory.
## Prerequesites
Set up your `.env` file to contain the following environment variables.
```
GH_TOKEN=github_pat_...(required, provides access to Vuln-Guard GitHub organization, only owners can have access)
SEMGREP_APP_TOKEN=...(optional)
```
## Testing Locally with Docker
### Build Docker Image
```
docker build -f src/backend/workflow/vuln_identify/Dockerfile -t vuln_identify .
```
### Run Docker Container
Sample command:
This uses the vuln scan results corresponding to `logging-log4j1`. This writes results to the path `/mnt/c/Users/jtyeu/MIDS/DATASCI_210/vuln-management-capstone/docker_artifacts`. Replace this with your own absolute path. Replace the other arguments as desired.
```
docker run  -v /mnt/c/Users/jtyeu/MIDS/DATASCI_210/vuln-management-capstone/docker_artifacts:/vuln_identify/artifacts --env-file .env vuln_identify --vuln_scan_results_path=artifacts/detect/logging-log4j1_vuln_scan_pd.parquet --dep_repos_root_dir_path=artifacts/identify/repos --output_raw_scans_dir_path=artifacts/identify/semgrep_scans --output_final_scans_dir_path=artifacts/identify/semgrep_scans --output_pd_path=artifacts/identify/logging-log4j1_vuln_identify_pd.parquet --display=True
```
Sample expected output: (exact output may vary but you should see final dataframe snippet)
```
Repo logging-log4j2 already forked to organization Vuln-Guard. Skipping forking.
Repo https://github.com/Vuln-Guard/logging-log4j2.git already cloned in artifacts/identify/repos/logging-log4j2. Skipping cloning.
Semgrep scan output file artifacts/identify/semgrep_scans/logging-log4j2_semgrep_scan.json already exists and is non-empty. Skipping semgrep scan.
finished semgrep scan.
Semgrep scan pandas dataframe file artifacts/identify/semgrep_scans/logging-log4j2_semgrep_scan_pd.parquet already exists and is non-empty. Skipping converting semgrep scan to pandas dataframe.
finished converting semgrep scan to pandas dataframe
Skipping vulnerability cve_id=CVE-2019-17571, package_name=log4j, package_version=1.2.17 as source_code_location is empty.
Repo logging-log4j1 already forked to organization Vuln-Guard. Skipping forking.
Repo https://github.com/Vuln-Guard/logging-log4j1.git already cloned in artifacts/identify/repos/logging-log4j1. Skipping cloning.
Semgrep scan output file artifacts/identify/semgrep_scans/logging-log4j1_semgrep_scan.json already exists and is non-empty. Skipping semgrep scan.
finished semgrep scan.
Semgrep scan pandas dataframe file artifacts/identify/semgrep_scans/logging-log4j1_semgrep_scan_pd.parquet already exists and is non-empty. Skipping converting semgrep scan to pandas dataframe.
finished converting semgrep scan to pandas dataframe
matching rows found in semgrep scan for vulnerability cve_id=CVE-2022-23305: 
                                                  path  ...  extra_dataflow_trace_taint_sink
41  artifacts/identify/repos/logging-log4j1/src/ma...  ...                              nan

[1 rows x 21 columns]
Skipping vulnerability cve_id=CVE-2022-23307, package_name=log4j, package_version=1.2.17 as source_code_location is empty.
Repo logging-log4j1 already forked to organization Vuln-Guard. Skipping forking.
Repo https://github.com/Vuln-Guard/logging-log4j1.git already cloned in artifacts/identify/repos/logging-log4j1. Skipping cloning.
Semgrep scan output file artifacts/identify/semgrep_scans/logging-log4j1_semgrep_scan.json already exists and is non-empty. Skipping semgrep scan.
finished semgrep scan.
Semgrep scan pandas dataframe file artifacts/identify/semgrep_scans/logging-log4j1_semgrep_scan_pd.parquet already exists and is non-empty. Skipping converting semgrep scan to pandas dataframe.
finished converting semgrep scan to pandas dataframe
           cve_id  ... extra_dataflow_trace_taint_sink
0   CVE-2021-4104  ...                             NaN
1  CVE-2022-23305  ...                             nan
2  CVE-2022-23302  ...                             NaN
3  CVE-2019-17571  ...                             NaN
4  CVE-2022-23307  ...                             NaN
5  CVE-2023-26464  ...                             NaN
6  CVE-2023-26464  ...                             NaN

[7 rows x 51 columns]
```
Locally, you should see the results written to the absolute path you specified above (e.g. `/mnt/c/Users/jtyeu/MIDS/DATASCI_210/vuln-management-capstone/docker_artifacts`)