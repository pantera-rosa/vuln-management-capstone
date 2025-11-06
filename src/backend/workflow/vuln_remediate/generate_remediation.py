import pandas as pd
from src.backend.utils.cmd import run_cmd_and_parse_output
from dotenv import load_dotenv
from typing import Optional, Dict
import os
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
import torch

load_dotenv()

GH_TOKEN = os.environ.get("GH_TOKEN", "")
GITHUB_ORG_NAME = "Vuln-Guard"

def generate_remediation(
    vuln_assess_df: pd.DataFrame,
    model_id: str,
    output_pd_path: str,
    with_quantization: bool = False
) -> pd.DataFrame:
    """
    Generate remediation suggestions for vulnerabilities in the given DataFrame.

    Args:
        vuln_assess_df (pd.DataFrame): DataFrame containing vulnerability assessments.
        output_pd_path (str): Path to save the output DataFrame with remediation suggestions.

    Returns:
        pd.DataFrame: DataFrame with remediation suggestions added.
    """
    output_vulns = []

    # iterate through vulnerabilities to generate remediation suggestions
    for _, row in vuln_assess_df.iterrows():
        if row["fixed_version"]:
            # if fixed, add recommendation to bump up version
            row['recommendation'] = f"Upgrade {row['package_name']} from existing vulnerable version {row['package_version']} to fixed version {row['fixed_version']}."
        elif row["source_code_location"]:
            # extract repo name from github url
            repo_name = row["source_code_location"].split("/")[-1]

            # ensure Vuln-Guard organization personal access token is provided in env vars so that gh CLI can be invoked successfully
            if not GH_TOKEN:
                raise ValueError("GH_TOKEN environment variable not set. Cannot authenticate with GitHub CLI. Please set GH_TOKEN to a valid GitHub personal access token with appropriate permissions.")
            
            # extract vulnerable code snippet if available
            code_snippet_dict = _extract_code_snippet_from_file(
                row['path'],
                row['extra_lines'],
                row['start_line'],
                row['start_col'],
                row['start_offset'],
                row['end_line'],
                row['end_col'],
                row['end_offset']
            )

            # generate remediation suggestion based on code snippet and other details
            if code_snippet_dict:
                # construct prompt for remediation generation
                prompt = _construct_prompt(row, code_snippet_dict)
                # load LLM model
                model, tokenizer = _load_llm(model_id, with_quantization=with_quantization)
                # invoke LLM with prompt to get remediation suggestion
                remediation_suggestion = _invoke_llm_model(model, tokenizer, prompt)
                row['recommendation'] = remediation_suggestion
                # create github issue with remediation suggestion
                git_issue_output = run_cmd_and_parse_output(["gh", "issue", "create", "-R", f"{GITHUB_ORG_NAME}/{repo_name}", "-t", f"{row['cve_id']} Remediation: {row['summary']}", "-b", f"{remediation_suggestion}", "--json url", "--jq", ".url"])
                row['remediation_github_url'] = git_issue_output
            else:
                print(f"Skipping vuln remediation for cve_id={row['cve_id']}, package_name={row['package_name']}, package_version={row['package_version']} as code snippet info is unavailable.")
        else:
            print(f"Skipping vuln remediation for cve_id={row['cve_id']}, package_name={row['package_name']}, package_version={row['package_version']} as source_code_location is empty.")

        # append resulting row to output
        output_vulns.append(row)

    output_df = pd.DataFrame(output_vulns)

    # save pandas dataframe to output_pd_path
    output_df.to_parquet(output_pd_path, index=False)

    return output_df

def _extract_code_snippet_from_file(
    path: str,
    extra_lines: Optional[str],
    start_line: Optional[str],
    start_col: Optional[str],
    start_offset: Optional[str],
    end_line: Optional[str],
    end_col: Optional[str],
    end_offset: Optional[str]
) -> Optional[Dict[str, str]]:
    code_snippet_dict = {}

    if extra_lines:
        code_snippet_dict['code_snippet'] = extra_lines

    # TODO: try to extract code snippet & context using start_offset and end_offset
    try:
        with open(path, 'rb') as f:  # Open in binary read mode
            f.seek(start_offset)
            snippet_bytes = f.read(end_offset - start_offset)
            code_snippet_dict['code_snippet'] = snippet_bytes.decode('utf-8')  # Decode to string (adjust encoding if needed)
            # set code_context as the sample of the file some bytes around the code_snippet
            context_bytes = f.read(end_offset + 100 - start_offset - 100)
            code_snippet_dict['code_context'] = context_bytes.decode('utf-8')
    except FileNotFoundError:
        print(f"Error: File not found at {path}. Could not extract code snippet info.")
    except Exception as e:
        print(f"An error occurred: {e}")

    # TODO: if code snippet & context could not be extracted, use start_line, start_col, end_line, and end_col
    pass
    

def _construct_prompt(row: pd.Series, code_snippet_info: Dict[str, str]) -> str:
    prompt = f"""
    Your task is to generate the code fix for the following vulnerable code snippet,
    given the provided supplementary information.

    Here is the supplementary information.
    The following information describes the nature of the vulnerability:
    - CVE ID: {row['cve_id']}
    - GHSA ID: {row['ghsa_id']}
    - CWE ID: {row['cwe_id']}
    - CWE Name: {row['cwe_name']}
    - Summary: {row['summary']}
    - Description: {row['description']}
    The following information describes the features and context of the
    vulnerable code snippet:
    - Language: {row['language']}
    - Filename: {row['filename']}
    - Extra message: {row['extra_message']}
    - Full vulnerable code file contents:
    ```
    {code_snippet_info['code_context']}
    ```

    Evaluate the vulnerable code snippet based on the supplementary vulnerability
    and code information.

    Here is the vulnerable code snippet:
    ```
    {code_snippet_info['code_snippet']}
    ```

    Then generate the code remediation. Use the 'Extra message', if provided, as a hint to generate the fix.
    Provide a valid patch, only showing the {row['language']} code changes needed rather than the entire patched code.
    Do not include additional text in your response.

    Patch code changes:
    ```
    """
    return prompt

def _load_llm(model_id: str, with_quantization : bool = False):
    quantization_config = None
    if with_quantization:
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
        )
    
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForCausalLM.from_pretrained(model_id, quantization_config=quantization_config, device_map="auto")
    return model, tokenizer

def _invoke_llm_model(model, tokenizer, prompt: str) -> str:
    messages = [
        {"role": "system", "content": "You are a cybersecurity engineer who is an expert at fixing vulnerable code."},
        {"role": "user", "content": prompt}
    ]

    inputs = tokenizer.apply_chat_template(
                        messages,
                        add_generation_prompt=True,
                        tokenize=True,
                        return_dict=True,
                        return_tensors="pt",
                    ).to(model.device)

    outputs = model.generate(
        **inputs,
        max_new_tokens=8192 # Increased the maximum number of new tokens
        )
    info = tokenizer.decode(outputs[0][inputs["input_ids"].shape[-1]:], skip_special_tokens=True)
    return info