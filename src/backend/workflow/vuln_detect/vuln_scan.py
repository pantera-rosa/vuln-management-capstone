"""
Run vulnerability scan.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict
import pandas as pd
import numpy as np
import os
from src.backend.workflow.vuln_detect.provider import fetch_ghsa_details
from src.backend.utils.cmd import run_cmd_and_parse_output
from dotenv import load_dotenv

load_dotenv()

GITHUB_PERSONAL_ACCESS_TOKEN = os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN", "")

def extract_sbom(dir_path: str, output_sbom_path: str) -> None:
	"""
	Extract SBOM from the given directory using syft and save it to the specified path (must end in '.spdx.json').
	Example usage:
		extract_sbom("/path/to/dir", "/path/to/sbom.spdx.json")
	"""
	# skip if output_sbom_path already exists and is non-empty
	if output_sbom_path and os.path.isfile(output_sbom_path) and os.path.getsize(output_sbom_path) > 0:
		print(f"SBOM file {output_sbom_path} already exists and is non-empty. Skipping SBOM extraction.")
		return
	
	# check if directory at dir_path is empty
	if not os.path.isdir(dir_path) or len(os.listdir(dir_path)) == 0:
		raise ValueError(f"Directory {dir_path} is empty or does not exist. Cannot extract SBOM.")
	
	# run syft to generate sbom
	syft_cmd = ["syft", "--from", "dir", dir_path, "-o", "spdx-json"]
	run_cmd_and_parse_output(syft_cmd, return_dict=False, output_path=output_sbom_path)

def perform_vuln_scan(sbom_path: str, output_scan_path: str = None, output_pd_path: str = None) -> pd.DataFrame:
	"""
	Perform vulnerability scan on the given SBOM path using grype and save the results to the specified output path (must end in '.parquet').
	Example usage:
		perform_vuln_scan("/path/to/sbom.spdx.json", "/path/to/vuln_scan_df.parquet")
	"""
	# skip if output_pd_path already exists and is non-empty
	if output_pd_path and os.path.isfile(output_pd_path) and os.path.getsize(output_pd_path) > 0:
		print(f"Vulnerability scan dataframe file {output_pd_path} already exists and is non-empty. Skipping vulnerability scan.")
		return pd.read_parquet(output_pd_path)
	# run grype scan on sbom_path
	# skip if output_scan_path already exists and is non-empty
	grype_scan_result = None
	if output_scan_path and os.path.isfile(output_scan_path) and os.path.getsize(output_scan_path) > 0:
		print(f"Grype scan output file {output_scan_path} already exists and is non-empty. Skipping grype scan.")
		with open(output_scan_path, "r") as f:
			grype_scan_result = json.load(f)
	else:
		grype_scan_result = _run_grype_scan(sbom_path, output_path=output_scan_path)
	print("finished grype scan.")
	# convert grype scan result to pandas dataframe
	result_df =  _extract_grype_df(grype_scan_result)
	print("finished converting grype scan to pandas dataframe")
	# save the result to output_pd_path
	result_df.to_parquet(output_pd_path, index=False)
	print("finished saving grype scan pandas dataframe")
	return result_df

def _extract_grype_df(grype_scan_result):
    grype_vulns = grype_scan_result.get("matches", [])
    grype_df = pd.json_normalize(grype_vulns)

	# Explode list fields into separate rows and normalize nested fields into separate columns
    grype_expanded_df = grype_df.explode("relatedVulnerabilities") if "relatedVulnerabilities" in grype_df.columns else grype_df
    grype_expanded_df = grype_expanded_df.explode("matchDetails") if "matchDetails" in grype_expanded_df.columns else grype_expanded_df
    grype_expanded_df = grype_expanded_df.explode("vulnerability.epss") if "vulnerability.epss" in grype_expanded_df.columns else grype_expanded_df
    grype_extracted_df = pd.concat([
    	grype_expanded_df.drop('relatedVulnerabilities', axis=1),
    	pd.json_normalize(grype_expanded_df['relatedVulnerabilities']).add_prefix('relatedVulnerabilities.')
	], axis=1) if "relatedVulnerabilities" in grype_expanded_df.columns else grype_expanded_df
    grype_extracted_df = pd.concat([
		grype_extracted_df.drop('matchDetails', axis=1),
		pd.json_normalize(grype_extracted_df['matchDetails']).add_prefix('matchDetails.')
	], axis=1) if "matchDetails" in grype_extracted_df.columns else grype_extracted_df
    grype_extracted_df = pd.concat([
		grype_extracted_df.drop('vulnerability.epss', axis=1),
		pd.json_normalize(grype_extracted_df['vulnerability.epss']).add_prefix('vulnerability.epss.')
	], axis=1) if "vulnerability.epss" in grype_extracted_df.columns else grype_extracted_df

	# extract CVE and GHSA IDs
    grype_extracted_df = _extract_grype_ghsa_and_cve_ids_df(grype_extracted_df)
	# extract cvss info
    grype_extracted_df = _extract_grype_cvss_df(grype_extracted_df)
	# extract ghsa info
    grype_extracted_df = _extract_grype_ghsa_df(grype_extracted_df)

    final_grype_dict = {
		"cve_id": grype_extracted_df['cve_id'],
		"ghsa_id": grype_extracted_df['ghsa_id'],
		"severity": grype_extracted_df["vulnerability.severity"] if "vulnerability.severity" in grype_extracted_df.columns else np.nan,
		"related_vuln_datasource": grype_extracted_df['relatedVulnerabilities.dataSource'] if 'relatedVulnerabilities.dataSource' in grype_extracted_df.columns else np.nan,
		"language": grype_extracted_df['artifact.language'] if 'artifact.language' in grype_extracted_df.columns else np.nan,
		"package_name": grype_extracted_df['artifact.name'] if 'artifact.name' in grype_extracted_df.columns else np.nan,
		"package_version": grype_extracted_df['artifact.version'] if 'artifact.version' in grype_extracted_df.columns else np.nan,
		"fixed_version": grype_extracted_df['matchDetails.fix.suggestedVersion'] if 'matchDetails.fix.suggestedVersion' in grype_extracted_df.columns else np.nan,
		"cvss_v2_score": grype_extracted_df['cvss_v2_vector'] if 'cvss_v2_vector' in grype_extracted_df.columns else np.nan,
		"cvss_v2_version": grype_extracted_df['cvss_v2_version'] if 'cvss_v2_version' in grype_extracted_df.columns else np.nan,
		"cvss_v2_base_score": grype_extracted_df['cvss_v2_base_score'] if 'cvss_v2_base_score' in grype_extracted_df.columns else np.nan,
		"cvss_v2_exploitability_score": grype_extracted_df['cvss_v2_exploitability_score'] if 'cvss_v2_exploitability_score' in grype_extracted_df.columns else np.nan,
		"cvss_v2_impact_score": grype_extracted_df['cvss_v2_impact_score'] if 'cvss_v2_impact_score' in grype_extracted_df.columns else np.nan,
		"cvss_v3_score": grype_extracted_df['cvss_v3_vector'] if 'cvss_v3_vector' in grype_extracted_df.columns else np.nan,
		"cvss_v3_version": grype_extracted_df['cvss_v3_version'] if 'cvss_v3_version' in grype_extracted_df.columns else np.nan,
		"cvss_v3_base_score": grype_extracted_df['cvss_v3_base_score'] if 'cvss_v3_base_score' in grype_extracted_df.columns else np.nan,
		"cvss_v3_exploitability_score": grype_extracted_df['cvss_v3_exploitability_score'] if 'cvss_v3_exploitability_score' in grype_extracted_df.columns else np.nan,
		"cvss_v3_impact_score": grype_extracted_df['cvss_v3_impact_score'] if 'cvss_v3_impact_score' in grype_extracted_df.columns else np.nan,
		"cvss_v4_score": grype_extracted_df['cvss_v4_vector'] if 'cvss_v4_vector' in grype_extracted_df.columns else np.nan,
		"cvss_v4_version": grype_extracted_df['cvss_v4_version'] if 'cvss_v4_version' in grype_extracted_df.columns else np.nan,
		"cvss_v4_base_score": grype_extracted_df['cvss_v4_base_score'] if 'cvss_v4_base_score' in grype_extracted_df.columns else np.nan,
		"cvss_v4_exploitability_score": grype_extracted_df['cvss_v4_exploitability_score'] if 'cvss_v4_exploitability_score' in grype_extracted_df.columns else np.nan,
		"cvss_v4_impact_score": grype_extracted_df['cvss_v4_impact_score'] if 'cvss_v4_impact_score' in grype_extracted_df.columns else np.nan,
		"epss_score": grype_extracted_df['vulnerability.epss.epss'] if 'vulnerability.epss.epss' in grype_extracted_df.columns else np.nan,
		"epss_percentile": grype_extracted_df['vulnerability.epss.percentile'] if 'vulnerability.epss.percentile' in grype_extracted_df.columns else np.nan,
		"summary": grype_extracted_df['vulnerability.description'] if 'vulnerability.description' in grype_extracted_df.columns else np.nan,
		"description": grype_extracted_df['relatedVulnerabilities.description'] if 'relatedVulnerabilities.description' in grype_extracted_df.columns else np.nan,
		"references": grype_extracted_df['relatedVulnerabilities.urls'] if 'relatedVulnerabilities.urls' in grype_extracted_df.columns else np.nan,
		"source_code_location": grype_extracted_df['source_code_location'] if 'source_code_location' in grype_extracted_df.columns else np.nan,
		"cwe_id": grype_extracted_df['cwes.cwe_id'] if 'cwes.cwe_id' in grype_extracted_df.columns else np.nan,
		"cwe_name": grype_extracted_df['cwes.name'] if 'cwes.name' in grype_extracted_df.columns else np.nan
	}

	# construct final dataframe
    return pd.DataFrame(final_grype_dict)

def _extract_grype_ghsa_and_cve_ids_df(df: pd.DataFrame) -> pd.DataFrame:
	"""
	Extract GHSA and CVE IDs from the grype dataframe.
	"""
	ghsa_ids = []
	cve_ids = []
	for _, row in df.iterrows():
		vuln_id = row['vulnerability.id'] if 'vulnerability.id' in row else None
		related_vuln_id = row['relatedVulnerabilities.id'] if 'relatedVulnerabilities.id' in row else None
		# extract GHSA ID
		if isinstance(vuln_id, str) and vuln_id.startswith("GHSA-"):
			ghsa_ids.append(vuln_id)
		elif isinstance(related_vuln_id, str) and related_vuln_id.startswith("GHSA-"):
			ghsa_ids.append(related_vuln_id)
		else:
			ghsa_ids.append(np.nan)
		# extract CVE ID
		if isinstance(vuln_id, str) and vuln_id.startswith("CVE-"):
			cve_ids.append(vuln_id)
		elif isinstance(related_vuln_id, str) and related_vuln_id.startswith("CVE-"):
			cve_ids.append(related_vuln_id)
		else:
			cve_ids.append(np.nan)
	df['ghsa_id'] = ghsa_ids
	df['cve_id'] = cve_ids
	return df

def _extract_grype_ghsa_df(df: pd.DataFrame) -> pd.DataFrame:
	"""
	Extract GHSA related info from the grype dataframe.
	For each vulnerability, if it has a GHSA ID, fetch the source code location and CWE info from the GitHub Advisory API.
	"""
	source_code_locations = []
	cwe_info = []
	for _, row in df.iterrows():
		ghsa_id = row['ghsa_id']

		if ghsa_id != np.nan:
			ghsa_json = fetch_ghsa_details(ghsa_id)
			github_link = ghsa_json['source_code_location'] if 'source_code_location' in ghsa_json else np.nan
			cwes = ghsa_json['cwes'] if 'cwes' in ghsa_json else np.nan
			source_code_locations.append(github_link)
			cwe_info.append(cwes)
		else:
			source_code_locations.append(np.nan)
			cwe_info.append(np.nan)
	df['source_code_location'] = source_code_locations
	df['cwes'] = cwe_info
	df = df.explode("cwes", ignore_index=True)
	df = pd.concat([
		df.drop('cwes', axis=1),
		pd.json_normalize(df['cwes']).add_prefix('cwes.')
	], axis=1)
	return df


def _extract_grype_cvss_df(df: pd.DataFrame) -> pd.DataFrame:
	cvss_metrics = df['vulnerability.cvss'] if 'vulnerability.cvss' in df.columns else None
	num_rows = len(df)
	nan_array = [np.nan] * num_rows
	cvss_dict = {
		"cvss_v2_vector": nan_array.copy(),
		"cvss_v2_version": nan_array.copy(),
		"cvss_v2_base_score": nan_array.copy(),
		"cvss_v2_exploitability_score": nan_array.copy(),
		"cvss_v2_impact_score": nan_array.copy(),
		"cvss_v3_vector": nan_array.copy(),
		"cvss_v3_version": nan_array.copy(),
		"cvss_v3_base_score": nan_array.copy(),
		"cvss_v3_exploitability_score": nan_array.copy(),
		"cvss_v3_impact_score": nan_array.copy(),
		"cvss_v4_vector": nan_array.copy(),
		"cvss_v4_version": nan_array.copy(),
		"cvss_v4_base_score": nan_array.copy(),
		"cvss_v4_exploitability_score": nan_array.copy(),
		"cvss_v4_impact_score": nan_array.copy()
	}

	if cvss_metrics is not None:
		for i in range(num_rows):
			cvss_info = cvss_metrics.iloc[i]
			cvss_v2_vector, cvss_v2_version, cvss_v2_base_score, cvss_v2_exploitability_score, cvss_v2_impact_score = np.nan, np.nan, np.nan, np.nan, np.nan
			cvss_v3_vector, cvss_v3_version, cvss_v3_base_score, cvss_v3_exploitability_score, cvss_v3_impact_score = np.nan, np.nan, np.nan, np.nan, np.nan
			cvss_v4_vector, cvss_v4_version, cvss_v4_base_score, cvss_v4_exploitability_score, cvss_v4_impact_score = np.nan, np.nan, np.nan, np.nan, np.nan
			if cvss_info:
				for cvss_version_info in cvss_info:
					version = cvss_version_info["version"]
					vector = cvss_version_info["vector"]
					metrics = cvss_version_info["metrics"]
					base_score = metrics["baseScore"]
					exploitability_score = metrics["exploitabilityScore"]
					impact_score = metrics["impactScore"]
					if version.startswith("2"):
						cvss_v2_vector = vector
						cvss_v2_version = version
						cvss_v2_base_score = base_score
						cvss_v2_exploitability_score = exploitability_score
						cvss_v2_impact_score = impact_score
					elif version.startswith("3"):
						cvss_v3_vector = vector
						cvss_v3_version = version
						cvss_v3_base_score = base_score
						cvss_v3_exploitability_score = exploitability_score
						cvss_v3_impact_score = impact_score
					else:
						cvss_v4_vector = vector
						cvss_v4_version = version
						cvss_v4_base_score = base_score
						cvss_v4_exploitability_score = exploitability_score
						cvss_v4_impact_score = impact_score
			cvss_dict['cvss_v2_vector'][i] = cvss_v2_vector
			cvss_dict['cvss_v2_version'][i] = cvss_v2_version
			cvss_dict['cvss_v2_base_score'][i] = cvss_v2_base_score
			cvss_dict['cvss_v2_exploitability_score'][i] = cvss_v2_exploitability_score
			cvss_dict['cvss_v2_impact_score'][i] = cvss_v2_impact_score
			cvss_dict['cvss_v3_vector'][i] = cvss_v3_vector
			cvss_dict['cvss_v3_version'][i] = cvss_v3_version
			cvss_dict['cvss_v3_base_score'][i] = cvss_v3_base_score
			cvss_dict['cvss_v3_exploitability_score'][i] = cvss_v3_exploitability_score
			cvss_dict['cvss_v3_impact_score'][i] = cvss_v3_impact_score
			cvss_dict['cvss_v4_vector'][i] = cvss_v4_vector
			cvss_dict['cvss_v4_version'][i] = cvss_v4_version
			cvss_dict['cvss_v4_base_score'][i] = cvss_v4_base_score
			cvss_dict['cvss_v4_exploitability_score'][i] = cvss_v4_exploitability_score
			cvss_dict['cvss_v4_impact_score'][i] = cvss_v4_impact_score

	cvss_df = pd.DataFrame(cvss_dict)
	return pd.concat([df.drop('vulnerability.cvss', axis=1), cvss_df], axis=1) if 'vulnerability.cvss' in df.columns else df


def _run_grype_scan(sbom_path: str, output_path: str = None) -> Dict[str, Any]:
	"""Run grype vuln scanning CLI on the given SBOM path and return the result.

	Input:
	- sbom_path: path to the SBOM file to scan.

	Output:
	- If grype produces valid JSON on stdout, the parsed Python object is returned.
	- If output_path is provided, the output will also be written to the specified file.

	Errors:
	- Raises FileNotFoundError if the grype executable is not found in PATH.
	- Raises RuntimeError if the grype invocation fails.
	"""
	grype_cmd = ["grype", f"sbom:{sbom_path}", "-o", "json"]
	return run_cmd_and_parse_output(grype_cmd, output_path=output_path)
