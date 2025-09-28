"""
Run vulnerability scan.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any


def scan(sbom_path: str) -> Any:
	"""Run the `grype` CLI on the given SBOM path and return the result.

	Inputs:
	- sbom_path: a string representing the path to the SBOM JSON file

	Output:
	- If grype produces valid JSON on stdout, the parsed Python object is returned.

	Errors:
	- Raises FileNotFoundError if the `grype` executable is not found in PATH.
	- Raises RuntimeError if the grype invocation fails.
	"""
	grype_cmd = ["grype", f"sbom:{sbom_path}", "--only-notfixed", "-o", "json"]
	proc = None
	try:
		proc = subprocess.run(grype_cmd, capture_output=True, text=True, check=True)
	except FileNotFoundError as e:
		raise FileNotFoundError("grype executable not found in PATH. Please install grype and ensure it's available.") from e
	except subprocess.CalledProcessError as e:
		raise e
	except Exception as e:
		raise RuntimeError("failed to run grype") from e
	
	stdout = proc.stdout if proc else ""
	# try parsing JSON
	try:
		return json.loads(stdout)
	except json.JSONDecodeError as e:
		# If output isn't JSON, fail.
		raise json.JSONDecodeError("grype output is not valid JSON", stdout, 0) from e