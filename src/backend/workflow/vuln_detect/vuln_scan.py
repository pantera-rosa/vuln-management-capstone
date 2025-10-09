"""
Run vulnerability scan.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import os
from typing import Any, Dict, List
import pandas as pd
import numpy as np
from src.backend.schemas.models import VulnScan


def detect_vulns(repo_url: str) -> List[VulnScan]:
    """
    Detect vulnerabilities in a repository by cloning it, generating an SBOM, and scanning.

    Args:
        repo_url: URL or path to the repository to scan

    Returns:
        List of VulnScan objects representing found vulnerabilities
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        # Clone the repository if it's a URL
        if repo_url.startswith(("http://", "https://", "git@")):
            clone_dir = os.path.join(temp_dir, "repo")
            _clone_repo(repo_url, clone_dir)
        else:
            # Assume it's a local path
            clone_dir = repo_url

        # Generate SBOM
        sbom_path = os.path.join(temp_dir, "sbom.spdx.json")
        extract_sbom(clone_dir, sbom_path)

        # Scan for vulnerabilities
        vulns = perform_vuln_scan(sbom_path)

        return vulns


def _clone_repo(repo_url: str, target_dir: str) -> None:
    """Clone a git repository to the target directory."""
    try:
        subprocess.run(
            ["git", "clone", repo_url, target_dir],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to clone repository {repo_url}: {e.stderr}") from e


def extract_sbom(dir_path: str, output_sbom_path: str) -> None:
    """
    Extract SBOM from the given directory using syft and save it to the specified path (must end in '.spdx.json').
    Example usage:
            extract_sbom("/path/to/dir", "/path/to/sbom.spdx.json")
    """
    # run syft to generate sbom
    syft_cmd = ["syft", "--from", "dir", dir_path, "-o", "spdx-json"]
    _run_cmd(syft_cmd, return_dict=False, output_path=output_sbom_path)


def perform_vuln_scan(sbom_path: str, output_pd_path: str = None) -> List[VulnScan]:
    """
    Perform vulnerability scan on the given SBOM path using grype and return VulnScan objects.
    Optionally save results to parquet file for backward compatibility.
    Example usage:
            vulns = perform_vuln_scan("/path/to/sbom.spdx.json")
            # or with parquet export:
            vulns = perform_vuln_scan("/path/to/sbom.spdx.json", "/path/to/vuln_scan_df.parquet")
    """
    # run grype scan on sbom_path
    grype_scan_result = _run_grype_scan(sbom_path)
    print("finished grype scan.")
    result_df = _extract_grype_df(grype_scan_result)
    print("finished converting grype scan to pandas dataframe")

    # convert DataFrame to VulnScan objects
    vulns = _df_to_vuln_scans(result_df)
    print(f"finished converting to {len(vulns)} VulnScan objects")

    # optionally save the result to output_pd_path for backward compatibility
    if output_pd_path:
        result_df.to_parquet(output_pd_path, index=False)
        print("finished saving grype scan pandas dataframe")

    return vulns


def _extract_grype_df(grype_scan_result):
    grype_vulns = grype_scan_result.get("matches", [])
    grype_df = pd.json_normalize(grype_vulns)

    # Explode list fields into separate rows
    grype_expanded_df = (
        grype_df.explode("relatedVulnerabilities")
        .explode("matchDetails")
        .explode("vulnerability.epss")
    )
    grype_extracted_df = pd.concat(
        [
            grype_expanded_df.drop("relatedVulnerabilities", axis=1),
            pd.json_normalize(grype_expanded_df["relatedVulnerabilities"]).add_prefix(
                "relatedVulnerabilities."
            ),
        ],
        axis=1,
    )
    grype_extracted_df = pd.concat(
        [
            grype_extracted_df.drop("matchDetails", axis=1),
            pd.json_normalize(grype_extracted_df["matchDetails"]).add_prefix(
                "matchDetails."
            ),
        ],
        axis=1,
    )
    grype_extracted_df = pd.concat(
        [
            grype_extracted_df.drop("vulnerability.epss", axis=1),
            pd.json_normalize(grype_extracted_df["vulnerability.epss"]).add_prefix(
                "vulnerability.epss."
            ),
        ],
        axis=1,
    )

    # normalize some nested fields into separate columns
    # extract cvss info
    cvss_df = _extract_grype_cvss_df(grype_extracted_df)
    grype_extracted_df = pd.concat(
        [grype_extracted_df.drop("vulnerability.cvss", axis=1), cvss_df], axis=1
    )
    final_grype_dict = {
        "id": grype_extracted_df["vulnerability.id"],
        "related_id": grype_extracted_df["relatedVulnerabilities.id"],
        "related_vuln_datasource": grype_extracted_df[
            "relatedVulnerabilities.dataSource"
        ],
        "language": grype_extracted_df["artifact.language"],
        "package_name": grype_extracted_df["artifact.name"],
        "package_version": grype_extracted_df["artifact.version"],
        "fixed_version": grype_extracted_df["matchDetails.fix.suggestedVersion"],
        "cvss_v2_score": grype_extracted_df["cvss_v2_vector"],
        "cvss_v2_version": grype_extracted_df["cvss_v2_version"],
        "cvss_v3_score": grype_extracted_df["cvss_v3_vector"],
        "cvss_v3_version": grype_extracted_df["cvss_v3_version"],
        "cvss_v4_vector": grype_extracted_df["cvss_v4_vector"],
        "cvss_v4_version": grype_extracted_df["cvss_v4_version"],
        "epss_score": grype_extracted_df["vulnerability.epss.epss"],
        "epss_percentile": grype_extracted_df["vulnerability.epss.percentile"],
        "summary": grype_extracted_df["vulnerability.description"],
        "description": grype_extracted_df["relatedVulnerabilities.description"],
        "references": grype_extracted_df["relatedVulnerabilities.urls"],
    }

    # construct final dataframe
    return pd.DataFrame(final_grype_dict)


def _df_to_vuln_scans(df: pd.DataFrame) -> List[VulnScan]:
    """Convert DataFrame to List[VulnScan] objects."""
    vulns = []
    for _, row in df.iterrows():
        # Handle NaN values by converting to None
        row_dict = row.to_dict()
        for key, value in row_dict.items():
            try:
                if pd.isna(value):
                    row_dict[key] = None
            except (TypeError, ValueError):
                # Handle cases where pd.isna fails (e.g., with lists)
                pass

        # Convert references from string to list if needed
        if isinstance(row_dict.get("references"), str):
            row_dict["references"] = (
                [row_dict["references"]] if row_dict["references"] else []
            )
        elif row_dict.get("references") is None:
            row_dict["references"] = []

        vulns.append(VulnScan(**row_dict))
    return vulns


def _extract_grype_cvss_df(df: pd.DataFrame) -> pd.DataFrame:
    cvss_metrics = df["vulnerability.cvss"]
    cvss_dict = {
        "cvss_v2_vector": [],
        "cvss_v2_version": [],
        "cvss_v3_vector": [],
        "cvss_v3_version": [],
        "cvss_v4_vector": [],
        "cvss_v4_version": [],
    }

    for _, cvss_info in cvss_metrics.items():
        (
            cvss_v2_vector,
            cvss_v2_version,
            cvss_v3_vector,
            cvss_v3_version,
            cvss_v4_vector,
            cvss_v4_version,
        ) = (np.nan, np.nan, np.nan, np.nan, np.nan, np.nan)
        if cvss_info:
            for cvss_version_info in cvss_info:
                version = cvss_version_info["version"]
                if version.startswith("2"):
                    cvss_v2_vector = cvss_version_info["vector"]
                    cvss_v2_version = version
                elif version.startswith("3"):
                    cvss_v3_vector = cvss_version_info["vector"]
                    cvss_v3_version = version
                else:
                    cvss_v4_vector = cvss_version_info["vector"]
                    cvss_v4_version = version
        cvss_dict["cvss_v2_vector"].append(cvss_v2_vector)
        cvss_dict["cvss_v2_version"].append(cvss_v2_version)
        cvss_dict["cvss_v3_vector"].append(cvss_v3_vector)
        cvss_dict["cvss_v3_version"].append(cvss_v3_version)
        cvss_dict["cvss_v4_vector"].append(cvss_v4_vector)
        cvss_dict["cvss_v4_version"].append(cvss_v4_version)

    return pd.DataFrame(cvss_dict)


def _run_cmd(
    cmd: list[str], return_dict: bool = True, output_path: str = None
) -> Dict[str, Any] | str:
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
        raise FileNotFoundError(
            f"{cmd[0]} executable not found in PATH. Please install {cmd[0]} and ensure it's available."
        ) from e
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
            raise json.JSONDecodeError(
                f"{cmd[0]} output is not valid JSON", output, 0
            ) from e

    # write to output_path if provided
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            if return_dict:
                json.dump(output, f, indent=4)
            else:
                f.write(output)
    return output


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
    grype_cmd = ["grype", f"sbom:{sbom_path}", "-o", "json"]
    return _run_cmd(grype_cmd)
