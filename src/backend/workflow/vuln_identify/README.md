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
This writes results to the path `/mnt/c/Users/jtyeu/MIDS/DATASCI_210/vuln-management-capstone/docker_artifacts`. Replace this with your own absolute path. Replace the other arguments as desired.
```
docker run  -v /mnt/c/Users/jtyeu/MIDS/DATASCI_210/vuln-management-capstone/docker_artifacts:/vuln_identify/artifacts --env-file .env vuln_identify --vuln_scan_results_path=artifacts/detect/verademo_scan_pd.parquet --dep_repos_root_dir_path=artifacts/identify/repos --output_raw_scans_dir_path=artifacts/identify/semgrep_scans --output_final_scans_dir_path=artifacts/identify/semgrep_scans --output_pd_path=artifacts/identify/semgrep_results_df.parquet --display=True
```
Sample expected output: (exact output may vary but you should see final dataframe snippet)
```
Repo mysql-connector-j already forked to organization Vuln-Guard. Skipping forking.
Repo https://github.com/Vuln-Guard/mysql-connector-j.git already cloned in artifacts/identify/repos/mysql-connector-j. Skipping cloning.
finished semgrep scan.
Saved semgrep extracted DataFrame to artifacts/identify/semgrep_scans/mysql-connector-j_semgrep_scan_pd.parquet
finished converting semgrep scan to pandas dataframe
              cve_id  ... extra_dataflow_trace_taint_sink
0     CVE-2022-22965  ...                             NaN
1     CVE-2022-22965  ...                             NaN
2      CVE-2015-7501  ...                             NaN
3      CVE-2024-8698  ...                             NaN
4   CVE-2016-1000031  ...                             NaN
5     CVE-2023-24998  ...                             NaN
6      CVE-2015-6420  ...                             NaN
7      CVE-2018-3258  ...                             NaN
8      CVE-2015-0886  ...                             NaN
9     CVE-2023-22102  ...                             NaN
10    CVE-2021-29425  ...                             NaN
11    CVE-2021-29425  ...                             NaN
12     CVE-2019-2692  ...                             NaN
13    CVE-2022-21363  ...                             NaN
14     CVE-2021-3827  ...                             NaN
15    CVE-2024-47554  ...                             NaN
16    CVE-2025-48976  ...                             NaN

[17 rows x 51 columns]
```
Locally, you should see the results written to the absolute path you specified above (e.g. `/mnt/c/Users/jtyeu/MIDS/DATASCI_210/vuln-management-capstone/docker_artifacts`)