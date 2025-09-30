"""
Run vulnerability scan.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any, Dict
from ...schemas.schemas import VulnScan

def perform_vuln_scan(sbom_path: str) -> VulnScan:
	# TODO: Merge results from grype and osv scans.
	# For now, just return an empty VulnScan object.
    grype_result = _run_grype_scan(sbom_path)
    osv_result = _run_osv_scan(sbom_path)
    return VulnScan(
		cve_id="",
		package_name="",
		version="",
		fix_version="",
		references=[]
	)

def _run_scan(cmd: list[str]) -> Dict[str, Any]:
	"""Run the vuln scanning CLI on the given SBOM path and return the result.

	Input:
	- cmd: a list of strings representing the command to run the vuln scanning CLI. Includes the SBOM path for the scan.

	Output:
	- If the CLI produces valid JSON on stdout, the parsed Python object is returned.

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

	stdout = proc.stdout if proc else ""
	# try parsing JSON
	try:
		return json.loads(stdout)
	except json.JSONDecodeError as e:
		# If output isn't JSON, fail.
		raise json.JSONDecodeError(f"{cmd[0]} output is not valid JSON", stdout, 0) from e

def _run_grype_scan(sbom_path: str) -> Dict[str, Any]:
	"""Run grype vuln scanning CLI on the given SBOM path and return the result.

	Input:
	- sbom_path: path to the SBOM file to scan.

	Output:
	- If grype produces valid JSON on stdout, the parsed Python object is returned.

	Errors:
	- Raises FileNotFoundError if the grype executable is not found in PATH.
	- Raises RuntimeError if the grype invocation fails.
	"""
	grype_cmd = ["grype", f"sbom:{sbom_path}", "--only-notfixed", "-o", "json"]
	return _run_scan(grype_cmd)

def _run_osv_scan(sbom_path: str) -> Dict[str, Any]:
	"""Run osv vuln scanning CLI on the given SBOM path and return the result.

	Input:
	- sbom_path: path to the SBOM file to scan.

	Output:
	- If osv produces valid JSON on stdout, the parsed Python object is returned.

	Errors:
	- Raises FileNotFoundError if the osv executable is not found in PATH.
	- Raises RuntimeError if the osv invocation fails.
	"""
	osv_cmd = ["osv-scanner", "scan", "source", "-L", sbom_path, "--format", "json"]
	return _run_scan(osv_cmd)