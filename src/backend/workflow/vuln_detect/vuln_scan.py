"""
Run vulnerability scan.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict
import re
import pandas as pd
import numpy as np
from pathlib import Path

def extract_sbom(dir_path: str, output_sbom_path: str = None) -> None:
	"""
	Extract SBOM from the given directory using syft and save it to the specified path (must end in '.spdx.json').
	Example usage:
		extract_sbom("/path/to/dir", "/path/to/sbom.spdx.json")
	"""
	# run syft to generate sbom
	syft_cmd = ["syft", "--from", "dir", dir_path, "-o", "spdx-json"]
	_run_cmd(syft_cmd, return_dict=False, output_path=output_sbom_path)

def perform_vuln_scan(sbom_path: str,
                      output_scan_path: str = None,
                      output_pd_path: str = None,
                      reachability_path: str = None,
                      src_root: str = None) -> pd.DataFrame:
	"""
	Perform vulnerability scan on the given SBOM path using grype and save the results to the specified output path (must end in '.parquet').
	Example usage:
		perform_vuln_scan("/path/to/sbom.spdx.json", "/path/to/vuln_scan_df.parquet")
	"""
	# run grype scan on sbom_path
	grype_scan_result = _run_grype_scan(sbom_path, output_path=output_scan_path)
	print("finished grype scan.")
	result_df =  _extract_grype_df(grype_scan_result)
	# merge optional reachability signal (external mapping and/or heuristic)
	result_df = _merge_reachability(
		result_df,
		reachability_path=reachability_path or os.getenv("REACHABILITY_PATH"),
		src_root=src_root or os.getenv("SRC_ROOT"),
	)
	print("finished converting grype scan to pandas dataframe")
	# save the result to output_pd_path
	result_df.to_parquet(output_pd_path, index=False)
	print("finished saving grype scan pandas dataframe")
	return result_df

def _extract_grype_df(grype_scan_result):
	grype_vulns = grype_scan_result.get("matches", [])
	grype_df = pd.json_normalize(grype_vulns)

	# Explode list fields into separate rows
	grype_expanded_df = grype_df.explode("relatedVulnerabilities").explode("matchDetails").explode("vulnerability.epss")
	grype_extracted_df = pd.concat([
		grype_expanded_df.drop('relatedVulnerabilities', axis=1),
		pd.json_normalize(grype_expanded_df['relatedVulnerabilities']).add_prefix('relatedVulnerabilities.')
	], axis=1)
	grype_extracted_df = pd.concat([
		grype_extracted_df.drop('matchDetails', axis=1),
		pd.json_normalize(grype_extracted_df['matchDetails']).add_prefix('matchDetails.')
	], axis=1)
	grype_extracted_df = pd.concat([
		grype_extracted_df.drop('vulnerability.epss', axis=1),
		pd.json_normalize(grype_extracted_df['vulnerability.epss']).add_prefix('vulnerability.epss.')
	], axis=1)
	
	# normalize some nested fields into separate columns
	# extract cvss info
	cvss_df = _extract_grype_cvss_df(grype_extracted_df)
	grype_extracted_df = pd.concat([grype_extracted_df.drop('vulnerability.cvss', axis=1), cvss_df], axis=1)
	final_grype_dict = {
		"id": grype_extracted_df['vulnerability.id'],
		"related_id": grype_extracted_df['relatedVulnerabilities.id'],
		"severity": grype_extracted_df["vulnerability.severity"],
		"related_vuln_datasource": grype_extracted_df['relatedVulnerabilities.dataSource'],
		"language": grype_extracted_df['artifact.language'],###
		"package_name": grype_extracted_df['artifact.name'],###
		"package_version": grype_extracted_df['artifact.version'],###
		"fixed_version": grype_extracted_df['matchDetails.fix.suggestedVersion'],
		"cvss_v2_score": grype_extracted_df['cvss_v2_vector'],###
		"cvss_v2_version": grype_extracted_df['cvss_v2_version'],
		"cvss_v2_base_score": grype_extracted_df['cvss_v2_base_score'],
		"cvss_v2_exploitability_score": grype_extracted_df['cvss_v2_exploitability_score'],
		"cvss_v2_impact_score": grype_extracted_df['cvss_v2_impact_score'],
		"cvss_v3_score": grype_extracted_df['cvss_v3_vector'],###
		"cvss_v3_version": grype_extracted_df['cvss_v3_version'],
		"cvss_v3_base_score": grype_extracted_df['cvss_v3_base_score'],
		"cvss_v3_exploitability_score": grype_extracted_df['cvss_v3_exploitability_score'],
		"cvss_v3_impact_score": grype_extracted_df['cvss_v3_impact_score'],
		"cvss_v4_vector": grype_extracted_df['cvss_v4_vector'],
		"cvss_v4_version": grype_extracted_df['cvss_v4_version'],
		"cvss_v4_base_score": grype_extracted_df['cvss_v4_base_score'],
		"cvss_v4_exploitability_score": grype_extracted_df['cvss_v4_exploitability_score'],
		"cvss_v4_impact_score": grype_extracted_df['cvss_v4_impact_score'],
		"epss_score": grype_extracted_df['vulnerability.epss.epss'],###
		"epss_percentile": grype_extracted_df['vulnerability.epss.percentile'],
		"summary": grype_extracted_df['vulnerability.description'],###
		"description": grype_extracted_df['relatedVulnerabilities.description'],###
		"references": grype_extracted_df['relatedVulnerabilities.urls']###
	}

	# construct final dataframe
	df = pd.DataFrame(final_grype_dict)
	if "reachable" not in df.columns:
        # Ensure presence of 'reachable' column for Option 6 (defaults to False)
		df["reachable"] = False
	return df
		

def _extract_grype_cvss_df(df: pd.DataFrame) -> pd.DataFrame:
	cvss_metrics = df['vulnerability.cvss']
	cvss_dict = {
		"cvss_v2_vector": [],
		"cvss_v2_version": [],
		"cvss_v2_base_score": [],
		"cvss_v2_exploitability_score": [],
		"cvss_v2_impact_score": [],
		"cvss_v3_vector": [],
		"cvss_v3_version": [],
		"cvss_v3_base_score": [],
		"cvss_v3_exploitability_score": [],
		"cvss_v3_impact_score": [],
		"cvss_v4_vector": [],
		"cvss_v4_version": [],
		"cvss_v4_base_score": [],
		"cvss_v4_exploitability_score": [],
		"cvss_v4_impact_score": []
	}

	for _,cvss_info in cvss_metrics.items():
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
		cvss_dict['cvss_v2_vector'].append(cvss_v2_vector)
		cvss_dict['cvss_v2_version'].append(cvss_v2_version)
		cvss_dict['cvss_v2_base_score'].append(cvss_v2_base_score)
		cvss_dict['cvss_v2_exploitability_score'].append(cvss_v2_exploitability_score)
		cvss_dict['cvss_v2_impact_score'].append(cvss_v2_impact_score)
		cvss_dict['cvss_v3_vector'].append(cvss_v3_vector)
		cvss_dict['cvss_v3_version'].append(cvss_v3_version)
		cvss_dict['cvss_v3_base_score'].append(cvss_v3_base_score)
		cvss_dict['cvss_v3_exploitability_score'].append(cvss_v3_exploitability_score)
		cvss_dict['cvss_v3_impact_score'].append(cvss_v3_impact_score)
		cvss_dict['cvss_v4_vector'].append(cvss_v4_vector)
		cvss_dict['cvss_v4_version'].append(cvss_v4_version)
		cvss_dict['cvss_v4_base_score'].append(cvss_v4_base_score)
		cvss_dict['cvss_v4_exploitability_score'].append(cvss_v4_exploitability_score)
		cvss_dict['cvss_v4_impact_score'].append(cvss_v4_impact_score)

	return pd.DataFrame(cvss_dict)


# -----------------------[ ADDED: reachability merge helper ]------------------------

def _merge_reachability(
	df: pd.DataFrame,
	reachability_path: str = None,
	src_root: str = None
) -> pd.DataFrame:
	"""
	Merge reachability into the scan DataFrame without altering existing fields.

	1) If reachability_path is provided and exists (CSV/JSON/NDJSON),
	   expect columns: id, package_name, reachable (True/False); merged by (id, package_name).
	2) Optional heuristic (Python): if env REACHABILITY_HEURISTIC=python and src_root is set,
	   set reachable=True when the package appears in import statements in the repo.

	Notes:
	- SCA vendors compute "reachable" via call-graph/context (e.g., Snyk Reachability, JFrog Xray Contextual Analysis).
	- Grype focuses on matching known CVEs; reachability is merged here for prioritization.
	"""
	# ensure presence (harmless if already present)
	if "reachable" not in df.columns:
		df["reachable"] = False

	# 1) external mapping (CSV/JSON/NDJSON)
	path = reachability_path
	if path and os.path.exists(path):
		try:
			ext = os.path.splitext(path)[1].lower()
			if ext in (".json", ".ndjson"):
				mapping = pd.read_json(path, lines=(ext == ".ndjson"))
			else:
				mapping = pd.read_csv(path)
			required = {"id", "package_name", "reachable"}
			missing = required - set(mapping.columns)
			if missing:
				raise ValueError(f"reachability file missing columns: {missing}")
			mapping = mapping[["id", "package_name", "reachable"]]
			df = df.merge(mapping, how="left", on=["id", "package_name"], suffixes=("", "_ext"))
			if "reachable_ext" in df.columns:
				df["reachable"] = df["reachable_ext"].fillna(df["reachable"]).fillna(False).astype(bool)
				df.drop(columns=["reachable_ext"], inplace=True, errors="ignore")
		except Exception as e:
			print(f"[reachability] merge skipped: {e}")  # non-fatal

	# 2) heuristic (Python)
	if os.getenv("REACHABILITY_HEURISTIC", "").lower() == "python" and src_root:
		def _is_imported(pkg: str) -> bool:
			if not isinstance(pkg, str) or not pkg:
				return False
			pat = re.compile(rf"^\s*(?:from\s+{re.escape(pkg)}\s+import|import\s+{re.escape(pkg)}(?:\s|\.|$))", re.M)
			try:
				for p in Path(src_root).rglob("*.py"):
					try:
						if pat.search(p.read_text(errors="ignore")):
							return True
					except Exception:
						continue
			except Exception:
				return False
			return False

		mask = df.get("language", pd.Series([""] * len(df))).fillna("").str.lower().eq("python")
		if "package_name" in df.columns:
			df.loc[mask, "reachable"] = (
				df.loc[mask].apply(lambda r: _is_imported(str(r["package_name"])), axis=1)
				| df.loc[mask, "reachable"]
			)

	df["reachable"] = df["reachable"].astype(bool)
	return df


def _run_cmd(cmd: list[str], return_dict: bool = True, output_path: str = None) -> Dict[str, Any]|str:
	"""Run the cmd and return the result.

	Input:
	- cmd: a list of strings representing the command to run.

	Output:
	- If the CLI produces valid JSON on stdout and return_dict is True, the parsed Python object is returned.
	- Otherwise, the raw stdout string is returned.
	- If output_path is provided, the output will also be written to the specified file.

	Errors:
	- Raises FileNotFoundError if the command executable is not found in PATH.
	- Raises RuntimeError if the command invocation fails.
	"""
	proc = None
	try:
		proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
	except FileNotFoundError as e:
		raise FileNotFoundError(f"{cmd[0]} executable not found in PATH. Please install {cmd[0]} and ensure it's available.") from e
	except subprocess.CalledProcessError as e:
		raise e
	except Exception as e:
		raise RuntimeError(f"failed to run {cmd[0]}") from e

	output = proc.stdout.strip() if proc else ""
	if return_dict:
		# try parsing JSON
		try:
			output = json.loads(output)
		except json.JSONDecodeError as e:
			# If output isn't JSON, fail.
			raise json.JSONDecodeError(f"{cmd[0]} output is not valid JSON", output, 0) from e
		
	# write to output_path if provided
	if output_path:
		directory = os.path.dirname(output_path)
		os.makedirs(directory, exist_ok=True)
		with open(output_path, "w") as f:
			if return_dict:
				json.dump(output, f, indent=4)
			else:
				f.write(output)
	return output

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
	return _run_cmd(grype_cmd, output_path=output_path)