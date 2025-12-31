# Vulnerability Detection
Contains scripts and Dockerfiles needed for vulnerability scanning. For other methods of testing locally with Poetry + Make or library usage, see root README.md. Run all of the following from the root directory.
## Prerequesites
Set up your `.env` file to contain the following environment variables.
```
GITHUB_PERSONAL_ACCESS_TOKEN=github_pat_...(optional, provides higher rate limits for GHSA API requests)
```
## Testing Locally with Docker
### Build Docker Image
```
docker build -f src/backend/workflow/vuln_detect/Dockerfile -t vuln_detect .
```
### Run Docker Container
Sample command:
This writes results to the path `/mnt/c/Users/jtyeu/MIDS/DATASCI_210/vuln-management-capstone/docker_artifacts`. Replace this with your own absolute path. Replace the other arguments as desired.
```
docker run  -v /mnt/c/Users/jtyeu/MIDS/DATASCI_210/vuln-management-capstone/docker_artifacts:/vuln_detect/artifacts --env-file .env vuln_detect --repo_url=https://github.com/veracode/verademo.git --dir_path=artifacts/repos/verademo --sbom_path=artifacts/detect/verademo_sbom.spdx.json --output_raw_scan_path=artifacts/detect/verademo_grype_sbom_scan.json --output_final_scan_path=artifacts/detect/verademo_scan_pd.parquet --display=True
```
Sample expected output: (exact output may vary but you should see final dataframe snippet)
```
Extracting SBOM from directory: artifacts/repos/verademo to artifacts/detect/verademo_sbom.spdx.json
Performing vulnerability scan on SBOM: artifacts/detect/verademo_sbom.spdx.json
finished grype scan.
finished converting grype scan to pandas dataframe
finished saving grype scan pandas dataframe
Vulnerability scan completed. Saved to artifacts/detect/verademo_scan_pd.parquet.
              cve_id  ...                                           cwe_name
0     CVE-2022-22965  ...  Improper Neutralization of Special Elements in...
1     CVE-2022-22965  ...  Improper Control of Generation of Code ('Code ...
2      CVE-2015-7501  ...                  Deserialization of Untrusted Data
3      CVE-2024-8698  ...   Improper Verification of Cryptographic Signature
4   CVE-2016-1000031  ...                            Improper Access Control
5     CVE-2023-24998  ...  Allocation of Resources Without Limits or Thro...
6      CVE-2015-6420  ...                  Deserialization of Untrusted Data
7      CVE-2018-3258  ...                      Improper Privilege Management
8      CVE-2015-0886  ...                     Integer Overflow or Wraparound
9     CVE-2023-22102  ...                                                NaN
10    CVE-2021-29425  ...                          Improper Input Validation
11    CVE-2021-29425  ...  Improper Limitation of a Pathname to a Restric...
12     CVE-2019-2692  ...  Access of Resource Using Incompatible Type ('T...
13    CVE-2022-21363  ...  Improper Handling of Insufficient Permissions ...
14     CVE-2021-3827  ...                            Improper Authentication
15    CVE-2024-47554  ...                  Uncontrolled Resource Consumption
16    CVE-2025-48976  ...  Allocation of Resources Without Limits or Thro...

[17 rows x 31 columns]
```
Locally, you should see the results written to the absolute path you specified above (e.g. `/mnt/c/Users/jtyeu/MIDS/DATASCI_210/vuln-management-capstone/docker_artifacts`)