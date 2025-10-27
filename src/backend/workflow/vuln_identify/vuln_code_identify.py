"""
Run vulnerability code identification for unfixed vulnerabilities.
"""

from __future__ import annotations
from typing import Dict, Any

import pandas as pd
import os
import json
from src.backend.utils.cmd import run_cmd, run_cmd_and_parse_output
from dotenv import load_dotenv
import numpy as np

load_dotenv()

GH_TOKEN = os.environ.get("GH_TOKEN", "")
SEMGREP_APP_TOKEN = os.environ.get("SEMGREP_APP_TOKEN", "")
GITHUB_ORG_NAME = "Vuln-Guard"

def vuln_code_identify(
        vuln_scan_df: pd.DataFrame, 
        dep_repos_root_dir_path: str,
        output_scans_dir_path: str | None, 
        output_scans_pd_dir_path: str, 
        output_pd_path: str) -> pd.DataFrame:
    """
    Run vulnerability code identification for unfixed vulnerabilities.

    Returns:
        pd.DataFrame: DataFrame containing vulnerability code identification results.
    """
    # skip if output_pd_path already exists and is non-empty
    if os.path.isfile(output_pd_path) and os.path.getsize(output_pd_path) > 0:
        print(f"Vulnerability code identification dataframe file {output_pd_path} already exists and is non-empty. Skipping vulnerability code identification.")
        return pd.read_parquet(output_pd_path)
    
    # identify unfixed vulnerabilities
    unfixed_vuln_df = vuln_scan_df[vuln_scan_df["fixed_version"].isnull()]

    # iterate through unfixed vulnerabilities and run code identification
    for _, row in unfixed_vuln_df.iterrows():
        repo_url = row["source_code_location"] + ".git" # source_code_location is github url without .git
        # extract repo name from github url
        repo_name = repo_url.split("/")[-1].replace(".git", "")
        # derive dir path to clone forked repo into
        dir_path = os.path.join(dep_repos_root_dir_path, repo_name)

        # ensure Vuln-Guard organization personal access token is provided in env vars so that gh CLI can be invoked successfully
        if not GH_TOKEN:
            raise ValueError("GH_TOKEN environment variable not set. Cannot authenticate with GitHub CLI. Please set GH_TOKEN to a valid GitHub personal access token with appropriate permissions.")

        # fork repo to Vuln-Guard organization if not already forked
        is_forked = None
        try:
            repo_info = run_cmd_and_parse_output(["gh", "repo", "view", f"{GITHUB_ORG_NAME}/{repo_name}", '--json', 'isFork'])
            is_forked = repo_info.get("isFork", False)
        except Exception:
            is_forked = False
        if not is_forked:
            run_cmd(["gh", "repo", "fork", repo_url, "--org", GITHUB_ORG_NAME, "--clone=false"])
            print(f"Forked repo {repo_url} to organization {GITHUB_ORG_NAME}")
        else:
            print(f"Repo {repo_name} already forked to organization {GITHUB_ORG_NAME}. Skipping forking.")

        # clone forked repo into dir_path if not already cloned
        forked_repo_url = f"https://github.com/{GITHUB_ORG_NAME}/{repo_name}.git"
        if repo_url and dir_path and (not os.path.exists(dir_path) or not os.listdir(dir_path)):
            run_cmd(["git", "clone", forked_repo_url, dir_path])
            print(f"Cloned repo {forked_repo_url} into {dir_path}")
        else:
            print(f"Repo {forked_repo_url} already cloned in {dir_path}. Skipping cloning.")

        # in order to get semgrep to work we need to tell git to trust the absolute dir_path because under the hood, semgrep runs `git -C <abs_dir_path> ls-files -z --cached`.
        abs_dir_path = os.path.abspath(dir_path)
        run_cmd(["git", "config", "--global", "--add", "safe.directory", abs_dir_path])

        # run semgrep scan on the cloned forked repo if corresponding pandas dataframe doesn't already exist
        output_scan_path = os.path.join(output_scans_dir_path, f"{repo_name}_semgrep_scan.json") if output_scans_dir_path else None
        if output_scan_path and os.path.isfile(output_scan_path) and os.path.getsize(output_scan_path) > 0:
            print(f"Semgrep scan output file {output_scan_path} already exists and is non-empty. Skipping semgrep scan.")
            with open(output_scan_path, "r") as f:
                semgrep_scan_result = json.load(f)
        else:
            # note: provide semgrep app token in env vars to get fuller results
            semgrep_scan_result = _run_semgrep_scan(dir_path, output_path=output_scan_path)
        print("finished semgrep scan.")

        # convert semgrep scan result to pandas dataframe if corresponding pandas dataframe doesn't already exist
        output_scan_pd_path = os.path.join(output_scans_pd_dir_path, f"{repo_name}_semgrep_scan_pd.parquet") if output_scans_pd_dir_path else None
        if output_scan_pd_path and os.path.isfile(output_scan_pd_path) and os.path.getsize(output_scan_pd_path) > 0:
            print(f"Semgrep scan pandas dataframe file {output_scan_pd_path} already exists and is non-empty. Skipping converting semgrep scan to pandas dataframe.")
            result_df = pd.read_parquet(output_scan_pd_path)
        else:
            result_df =  _extract_semgrep_df(semgrep_scan_result, output_path=output_scan_pd_path)
        print("finished converting semgrep scan to pandas dataframe")

        # combine semgrep scan result dataframe with vuln_scan_df on matching cwe_id and filename in summary, description, or references
        cwe_id = row["cwe_id"]
        result_df = result_df[result_df.apply(lambda r: (r['cwe_id'] ==  cwe_id) & any(r['filename'] in str(row[col]) for col in ['summary', 'description']), axis=1)]
        output_df = pd.merge(vuln_scan_df, result_df, how="left", on="cwe_id")
    # save output DataFrame to parquet
    output_df.to_parquet(output_pd_path)

    return output_df

def _run_semgrep_scan(dir_path: str, output_path: str | None, num_subprocesses=10) -> Dict[str, Any]:
    """
    Run semgrep scan on the given directory.

    Args:
        dir_path (str): Path to the directory to scan.
        output_path (str | None): Path to save the semgrep scan output JSON file. If None, output is not saved to file.

    Returns:
        Dict[str, Any]: Semgrep scan result as a dictionary.
    """
    semgrep_cmd = [
        "semgrep",
        "scan",
        dir_path,
        "-j",
        str(num_subprocesses),
        "--json",
        "--dataflow-traces"
    ]
    if output_path:
        semgrep_cmd.extend(["--json-output", output_path])

    return run_cmd_and_parse_output(semgrep_cmd)

def _extract_semgrep_df(semgrep_result: Dict[str, Any], output_path: str) -> pd.DataFrame:
    """
    Extract relevant information from semgrep scan result and convert to pandas DataFrame.

    Args:
        semgrep_result (Dict[str, Any]): Semgrep scan result as a dictionary.

    Returns:
        pd.DataFrame: DataFrame containing relevant semgrep scan information.
    """
    semgrep_df = pd.json_normalize(semgrep_result["results"])
    # if extra.dataflow_trace fields are missing, add them with NaN values
    for col in ['extra.dataflow_trace.taint_source', 'extra.dataflow_trace.intermediate_vars', 'extra.dataflow_trace.taint_sink']:
        if col not in semgrep_df.columns:
            semgrep_df[col] = np.nan
    # extract relevant columns
    relevant_columns = ['path', 'start.line', 'start.col', 'start.offset', 'end.line', 'end.col', 'end.offset', 'extra.message', 'extra.metadata.cwe', "extra.metadata.likelihood", "extra.metadata.impact", "extra.metadata.confidence", "extra.metadata.vulnerability_class", "extra.severity", "extra.lines", "extra.validation_state", "extra.fix", "extra.dataflow_trace.taint_source", "extra.dataflow_trace.intermediate_vars", "extra.dataflow_trace.taint_sink"]
    semgrep_extracted_df = semgrep_df[relevant_columns] 
    semgrep_extracted_df = semgrep_extracted_df.explode(['extra.metadata.cwe'])
    semgrep_extracted_df[['cwe_id', 'cwe_name']] = semgrep_extracted_df['extra.metadata.cwe'].str.split(': ', expand=True)
    semgrep_extracted_df.drop(columns=['cwe_name','extra.metadata.cwe'], inplace=True)
    semgrep_extracted_df['filename'] = semgrep_extracted_df['path'].apply(lambda x: x.split('/')[-1].split('.')[0])
    # convert taint_source, intermediate_vars, taint_sink lists to strings
    semgrep_extracted_df['extra_dataflow_trace_taint_source'] = semgrep_extracted_df['extra.dataflow_trace.taint_source'].astype(str)
    semgrep_extracted_df['extra_dataflow_trace_intermediate_vars'] = semgrep_extracted_df['extra.dataflow_trace.intermediate_vars'].astype(str)
    semgrep_extracted_df['extra_dataflow_trace_taint_sink'] = semgrep_extracted_df['extra.dataflow_trace.taint_sink'].astype(str)
    semgrep_extracted_df.drop(columns=['extra.dataflow_trace.taint_source', 'extra.dataflow_trace.intermediate_vars', 'extra.dataflow_trace.taint_sink'], inplace=True)
    # rename columns with dots removed
    semgrep_extracted_df.columns = semgrep_extracted_df.columns.str.replace('.', '_')

    # save to parquet if output_path is provided
    if output_path:
        semgrep_extracted_df.to_parquet(output_path)
        print(f"Saved semgrep extracted DataFrame to {output_path}")

    return semgrep_extracted_df