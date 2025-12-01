from __future__ import annotations
import pandas as pd
from src.backend.utils.cmd import run_cmd_and_parse_output, run_cmd
from src.backend.utils.df import save_df
from dotenv import load_dotenv
from typing import Optional, Dict
import os
from pathlib import Path
from src.backend.utils.llm import load_llm, invoke_llm_model
from src.backend.aws.sagemaker.sagemaker import invoke_sagemaker_endpoint
import re

load_dotenv()

GH_TOKEN = os.environ.get("GH_TOKEN", "")
GITHUB_ORG_NAME = "Vuln-Guard"


def generate_remediation(
    vuln_df: pd.DataFrame,
    model_id: str,
    output_pd_path: str,
    dep_repos_root_dir_path: str,
    with_quantization: bool = True,
    save_csv: bool = True,
    use_sagemaker: bool = False,
    sagemaker_endpoint_name: Optional[str] = None,
    aws_region: Optional[str] = None,
) -> pd.DataFrame:
    """
    Generate remediation suggestions for vulnerabilities in the given DataFrame.

    Args:
        vuln_df (pd.DataFrame): DataFrame containing vulnerability assessments.
        model_id (str): Model ID for LLM to use in remediation generation.
        output_pd_path (str): Path to save the output DataFrame with remediation suggestions in JSON format.
        dep_repos_root_dir_path (str): Root directory path for dependency repositories.
        with_quantization (bool): Whether to use 4-bit quantization for the LLM.
        save_csv (bool): Whether to also save results as CSV (default: True).
        use_sagemaker (bool): Whether to use SageMaker endpoint instead of local LLM model.
        sagemaker_endpoint_name (str, optional): Name of SageMaker endpoint (required if use_sagemaker=True).
        aws_region (str, optional): AWS region for SageMaker (defaults to us-east-1).

    Returns:
        pd.DataFrame: DataFrame with remediation suggestions added.
    """
    # skip if output_pd_path already exists and is non-empty
    if os.path.isfile(output_pd_path) and os.path.getsize(output_pd_path) > 0:
        print(
            f"Vulnerability code remediation dataframe file {output_pd_path} already exists and is non-empty. Skipping vulnerability code remediation."
        )
        return pd.read_json(output_pd_path)

    output_vulns = []
    
    # Load model once if using local LLM (more efficient than loading per vulnerability)
    model = None
    tokenizer = None
    if not use_sagemaker:
        print(f"📥 Pre-loading local LLM model: {model_id}")
        print(f"   This may take a minute...")
        model, tokenizer = load_llm(model_id, with_quantization=with_quantization)
        print(f"   ✅ Model loaded and ready for {len(vuln_df)} vulnerabilities")

    # iterate through vulnerabilities to generate remediation suggestions
    for idx, row in vuln_df.iterrows():
        if row["fixed_version"]:
            # if fixed, add recommendation to bump up version
            print(
                f"[{idx+1}/{len(vuln_df)}] {row['cve_id']}: Using fixed version (no LLM needed)"
            )
            row["recommendation"] = (
                f"Upgrade {row['package_name']} from existing vulnerable version {row['package_version']} to fixed version {row['fixed_version']}."
            )
        elif row["source_code_location"] and row["path"]:
            # extract repo name from github url
            repo_name = row["source_code_location"].split("/")[-1]

            # ensure Vuln-Guard organization personal access token is provided in env vars so that gh CLI can be invoked successfully
            if not GH_TOKEN:
                raise ValueError(
                    "GH_TOKEN environment variable not set. Cannot authenticate with GitHub CLI. Please set GH_TOKEN to a valid GitHub personal access token with appropriate permissions."
                )

            # rewrite path to have root directory dep_repos_root_dir_path
            file_path = Path(row["path"])
            file_path_parts = file_path.parts
            start_index = file_path_parts.index(repo_name)
            # Reconstruct the path from the repo folder onwards
            portion = Path(*file_path_parts[start_index:])
            path = os.path.join(dep_repos_root_dir_path, str(portion))

            # extract vulnerable code snippet if available
            code_snippet_dict = _extract_code_snippet(
                path,
                row["extra_lines"],
                row["start_line"],
                row["start_col"],
                row["start_offset"],
                row["end_line"],
                row["end_col"],
                row["end_offset"],
            )

            # generate remediation suggestion based on code snippet and other details
            if code_snippet_dict["code_snippet"] and code_snippet_dict["file_contents"]:
                # extract java code context manually. If code is not java, this should return empty string
                code_snippet_dict = _extract_java_code_context_manual(
                    row, code_snippet_dict
                )
                # invoke LLM with prompt to get remediation suggestion
                if use_sagemaker:
                    print(
                        f"[SageMaker] Calling endpoint for remediation of {row['cve_id']}"
                    )
                    # if code context is empty, use sagemaker to extract code context
                    if not code_snippet_dict.get("code_context"):
                        code_snippet_dict = _extract_code_context_sagemaker(
                            row,
                            code_snippet_dict,
                            sagemaker_endpoint_name,
                            aws_region,
                        )
                    prompt = _construct_prompt(row, code_snippet_dict)
                    remediation_suggestion = invoke_sagemaker_endpoint(
                        prompt=prompt,
                        endpoint_name=sagemaker_endpoint_name,
                        region=aws_region,
                    )
                    print(f"✅ [SageMaker] Received response for {row['cve_id']}")
                else:
                    # use local LLM model (already loaded above)
                    print(f"[Local LLM] Generating remediation for {row['cve_id']} ({idx+1}/{len(vuln_df)})")
                    # if code context is empty, use local llm to extract code context
                    if not code_snippet_dict.get("code_context"):
                        code_snippet_dict = _extract_code_context(
                            model, tokenizer, row, code_snippet_dict
                        )
                    prompt = _construct_prompt(row, code_snippet_dict)
                    remediation_suggestion = invoke_llm_model(model, tokenizer, prompt)
                    print(f"✅ [Local LLM] Received response for {row['cve_id']}")

                row["recommendation"] = remediation_suggestion
                # create github issue with remediation suggestion
                run_cmd(
                    [
                        "gh",
                        "repo",
                        "edit",
                        f"{GITHUB_ORG_NAME}/{repo_name}",
                        "--enable-issues",
                    ]
                )
                git_issue_output = run_cmd_and_parse_output(
                    [
                        "gh",
                        "issue",
                        "create",
                        "-R",
                        f"{GITHUB_ORG_NAME}/{repo_name}",
                        "-t",
                        f"{row['cve_id']} Remediation: {row['summary']}",
                        "-b",
                        f"{remediation_suggestion}",
                    ],
                    return_dict=False,
                )
                row["remediation_github_url"] = git_issue_output
            else:
                print(
                    f"Skipping vuln remediation for cve_id={row['cve_id']}, package_name={row['package_name']}, package_version={row['package_version']} as code snippet info is unavailable."
                )
        else:
            print(
                f"Skipping vuln remediation for cve_id={row['cve_id']}, package_name={row['package_name']}, package_version={row['package_version']} as source_code_location and/or path is empty."
            )

        # append resulting row to output
        output_vulns.append(row)

    output_df = pd.DataFrame(output_vulns)

    # save pandas dataframe to output_pd_path (json)
    save_df(output_df, output_pd_path, format="json")
    print(f"Saved remediation results to JSON path: {output_pd_path}")

    # also save as CSV if requested
    if save_csv:
        csv_path = output_pd_path.replace(".json", ".csv")
        save_df(output_df, csv_path, format="csv")
        print(f"Remediation results also saved to CSV path: {csv_path}")

    return output_df


def _extract_code_snippet(
    path: str,
    extra_lines: Optional[str],
    start_line: Optional[str],
    start_col: Optional[str],
    start_offset: Optional[str],
    end_line: Optional[str],
    end_col: Optional[str],
    end_offset: Optional[str],
) -> Dict[str, str]:
    """
    Extract vulnerable code snippet from cloned git fork file, based on path and position information provided.
    Also store the full file contents.
    """
    code_snippet_dict = {"code_snippet": None, "file_contents": None}
    print("Starting code snippet extraction...")

    # try to extract code snippet from extra_lines
    if extra_lines:
        code_snippet_dict["code_snippet"] = extra_lines
        print(
            f"successfully extracted code snippet using extra_lines. Code snippet: {code_snippet_dict['code_snippet']}"
        )

    # if code snippet could not be extracted, use start_offset and end_offset
    if not code_snippet_dict["code_snippet"] and start_offset and end_offset:
        try:
            with open(path, "rb") as f:  # Open in binary read mode
                f.seek(start_offset)
                snippet_bytes = f.read(end_offset - start_offset)
                code_snippet_dict["code_snippet"] = snippet_bytes.decode(
                    "utf-8"
                )  # Decode to string (adjust encoding if needed)
                print(
                    f"successfully extracted code snippet using start_offset and end_offset. Code snippet: {code_snippet_dict['code_snippet']}"
                )
        except FileNotFoundError:
            print(
                f"Error: File not found at {path}. Could not extract code snippet info."
            )
            return code_snippet_dict
        except Exception as e:
            print(
                f"An error occurred while extracting code snippet from start_offset and end_offset: {e}"
            )

    # if code snippet could not be extracted, use start_line, start_col, end_line, and end_col
    if (
        not code_snippet_dict["code_snippet"]
        and start_line
        and start_col
        and end_line
        and end_col
    ):
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # Ensure valid line range
            if start_line < 1 or end_line > len(lines):
                raise ValueError("Line numbers are out of range.")

            # Convert to 0-based for Python indexing
            start_line_idx = start_line - 1
            end_line_idx = end_line - 1

            # Single-line case
            if start_line == end_line:
                return lines[start_line_idx][start_col - 1 : end_col]

            # Multi-line case
            extracted_lines = [
                lines[start_line_idx][start_col - 1 :]
            ]  # start line (partial)
            extracted_lines.extend(
                lines[start_line_idx + 1 : end_line_idx]
            )  # full middle lines
            extracted_lines.append(lines[end_line_idx][:end_col])  # end line (partial)

            code_snippet_dict["code_snippet"] = "".join(extracted_lines)
            print(
                f"successfully extracted code snippet using start_line, start_col, end_line, and end_offset."
            )
        except Exception as e:
            print(
                f"An error occurred while extracting code snippet from start_line, start_col, end_line, and end_col: {e}"
            )

    # store full file contents in dict
    try:
        with open(path, "r", encoding="utf-8") as f:
            code_snippet_dict["file_contents"] = f.read()
            print(f"successfully extracted code file contents.")
    except Exception as e:
        print(f"An error occurred while extracting full file contents: {e}")

    return code_snippet_dict


def _extract_code_context(
    model, tokenizer, row: pd.Series, code_snippet_dict: Dict[str, str]
) -> Dict[str, str]:
    """
    Use LLM to extract code context corresponding to vulnerable code snippet and file contents.
    """
    if code_snippet_dict:
        code_extract_prompt = _construct_extract_code_context_prompt(
            row, code_snippet_dict
        )
        # invoke LLM to extract code context
        code_snippet_dict["code_context"] = invoke_llm_model(
            model, tokenizer, code_extract_prompt
        )
    return code_snippet_dict


def _extract_code_context_sagemaker(
    row: pd.Series,
    code_snippet_dict: Dict[str, str],
    sagemaker_endpoint_name: Optional[str],
    aws_region: Optional[str],
) -> Dict[str, str]:
    """
    Use SageMaker endpoint to extract code context corresponding to vulnerable code snippet and file contents.
    """
    if code_snippet_dict:
        code_extract_prompt = _construct_extract_code_context_prompt(
            row, code_snippet_dict
        )
        # invoke SageMaker endpoint to extract code context
        code_snippet_dict["code_context"] = invoke_sagemaker_endpoint(
            prompt=code_extract_prompt,
            endpoint_name=sagemaker_endpoint_name,
            region=aws_region,
            max_tokens=2048,  # Code context extraction needs less tokens
        )
    return code_snippet_dict


def _extract_java_code_context_manual(
    row: pd.Series, code_snippet_dict: Dict[str, str]
) -> Dict[str, str]:
    """
    Extracts the full code of the enclosing Java method for a given line number.

    Args:
        full_code: The complete Java source code as a string.
        line_number: The 1-based line number of the target snippet.

    Returns:
        The extracted method code as a string, or an empty string if not found.
    """
    full_code = code_snippet_dict.get("file_contents", "")
    line_number = int(row.get("start_line", 0))
    lines = full_code.splitlines()
    if not (1 <= line_number <= len(lines)):
        return ""  # Line number out of bounds

    # Adjust to 0-based index
    target_index = line_number - 1

    # Step 1: Find the method signature by searching upwards from the target line
    method_start_index = -1
    # Regex for Java method signature (simplified, may need refinement for all cases)
    # This pattern looks for access modifiers, return type, method name, and parameters
    method_signature_pattern = re.compile(
        r"^\s*(public|protected|private|static|final|abstract|synchronized|native)?\s+"
        r"(<[\w,\s]+>)?\s*[\w\d_]+\s+[\w\d_]+\s*\(.*?\)\s*(throws\s+[\w\d_,\s]+)?\s*\{"
    )

    for i in range(target_index, -1, -1):
        line = lines[i]
        # Check if the line looks like a method signature. We're looking for the line *containing* the { or ending with {.
        if re.search(method_signature_pattern, line.strip()):
            method_start_index = i
            break

    if method_start_index == -1:
        # If the direct signature regex failed, try a more general search for method-like structure
        # looking for public/protected/private, return type, method name, and opening parenthesis
        for i in range(target_index, -1, -1):
            line = lines[i].strip()
            if re.match(r"^(public|protected|private)\s+.*?\s+.*?\s*\(", line):
                method_start_index = i
                break
        if method_start_index == -1:
            return ""  # Could not find an enclosing method signature

    # Step 2: Find the corresponding closing brace for the method body
    brace_count = 0
    method_end_index = -1

    # Start counting braces from the method signature line
    for i in range(method_start_index, len(lines)):
        line = lines[i]
        brace_count += line.count("{")
        brace_count -= line.count("}")

        if brace_count == 0 and "}" in line:
            method_end_index = i
            break

    if method_end_index == -1:
        return ""  # Unbalanced braces or method end not found

    code_snippet_dict["code_context"] = "\n".join(
        lines[method_start_index : method_end_index + 1]
    )

    print("successfully extracted java code context manually.")
    return code_snippet_dict


def _construct_extract_code_context_prompt(
    row: pd.Series, code_snippet_dict: Dict[str, str]
) -> str:
    """
    Construct LLM prompt for code context extraction.
    """
    code_extract_prompt = f"""
    You are a cybersecurity engineer who is an expert at fixing vulnerable code.
    Extract the {row['language']} code from the code file contents that is relevant to the provided code snippet.
    Code file contents:
    ```
    {code_snippet_dict['file_contents']}
    ```
    code snippet:
    ```
    {code_snippet_dict['code_snippet']}
    ```
    Provide only the extracted {row['language']} code for the taint flow in the output. Do not just return the code snippet.

    extracted code:
    ```
    """
    return code_extract_prompt


def _construct_prompt(row: pd.Series, code_snippet_info: Dict[str, str]) -> str:
    """
    Construct LLM prompt for code remediation.
    """
    # Get code snippet - should always be present
    code_snippet = code_snippet_info.get("code_snippet", "")

    # Use code_context if available, otherwise use file_contents
    code_context = code_snippet_info.get("code_context") or code_snippet_info.get(
        "file_contents", ""
    )

    # Generate remediation guidance
    remediation_hint = f"Fix the {row.get('cwe_name', 'this')} vulnerability. Apply standard security best practices for this type of issue. {row.get('extra_message', '')}"

    prompt = f"""
    You are a cybersecurity engineer who is an expert at fixing vulnerable code.
    Your task is to generate the code fix for the following vulnerable code snippet.

    VULNERABILITY INFORMATION:
    - CVE ID: {row['cve_id']}
    - CWE ID: {row['cwe_id']} - {row['cwe_name']}
    - Summary: {row['summary']}
    - Description: {row['description']}

    CODE CONTEXT (Full file around vulnerable code):
    ```
    {code_context}
    ```

    VULNERABLE CODE SNIPPET:
    ```
    {code_snippet}
    ```

    REMEDIATION GUIDANCE:
    {remediation_hint}

    REQUIREMENTS:
    1. Fix the vulnerability described in the CWE
    2. Keep the same function signature and return type, unless a change is absolutely necessary to fix the vulnerability.
    3. Maintain compatibility with the rest of the code
    4. Only output the patched code - no explanations or comments. Omit the closing ``` markers.
    5. Output valid, compilable {row['language']} code

    PATCHED CODE:
    ```
    """
    return prompt
