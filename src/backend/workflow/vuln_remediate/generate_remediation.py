from __future__ import annotations
import pandas as pd
from src.backend.utils.cmd import run_cmd_and_parse_output
from dotenv import load_dotenv
from typing import Optional, Dict
import os
from pathlib import Path
from src.backend.utils.llm import load_llm, invoke_llm_model

load_dotenv()

GH_TOKEN = os.environ.get("GH_TOKEN", "")
GITHUB_ORG_NAME = "Vuln-Guard"

def generate_remediation(
    vuln_df: pd.DataFrame,
    model_id: str,
    output_pd_path: str,
    dep_repos_root_dir_path: str,
    with_quantization: bool = False
) -> pd.DataFrame:
    """
    Generate remediation suggestions for vulnerabilities in the given DataFrame.
    Saves results to both Parquet and CSV formats.
    Loads from either format if already exists.
    Preserves all columns from input DataFrame.
    """
    csv_path = output_pd_path.rsplit('.', 1)[0] + '.csv'
    
    # ✅ Try to load existing data from either format
    df = None
    
    # Try Parquet first
    if os.path.isfile(output_pd_path) and os.path.getsize(output_pd_path) > 0:
        try:
            print(f"Found existing Parquet file: {output_pd_path}")
            df = pd.read_parquet(output_pd_path)
            print(f"✅ Successfully loaded data from Parquet file")
        except Exception as e:
            print(f"⚠️  Could not read Parquet file: {e}")
            df = None
    
    # Try CSV if Parquet failed or doesn't exist
    if df is None and os.path.isfile(csv_path) and os.path.getsize(csv_path) > 0:
        try:
            print(f"Found existing CSV file: {csv_path}")
            df = pd.read_csv(csv_path, quoting=1, escapechar='\\', on_bad_lines='warn', engine='python')
            print(f"✅ Successfully loaded data from CSV file")
        except Exception as e:
            print(f"⚠️  Could not read CSV file: {e}")
            df = None
    
    # If we successfully loaded cached data
    if df is not None:
        print("Using cached vulnerability remediation data. Skipping regeneration.")
        
        # ✅ Ensure recommendation column exists
        if 'recommendation' not in df.columns:
            print("WARNING: 'recommendation' column missing from cached file. Adding it now...")
            df['recommendation'] = "Remediation not available"
        
        return df
    
    # ✅ No cached data found, generate fresh remediations
    print("No valid cached data found. Generating fresh remediation suggestions...")
    
    # ✅ Store original columns to preserve them
    original_columns = vuln_df.columns.tolist()
    print(f"📋 Input DataFrame has {len(original_columns)} columns")
    
    output_vulns = []

    # iterate through vulnerabilities to generate remediation suggestions
    for idx, row in vuln_df.iterrows():
        # ✅ Convert row to dict to preserve all columns
        row_dict = row.to_dict()
        
        # Initialize recommendation and remediation_github_url
        row_dict['recommendation'] = None
        if 'remediation_github_url' not in row_dict:
            row_dict['remediation_github_url'] = None
        
        # ✅ Debug: Print row info
        print(f"\n--- Processing row {idx} ---")
        print(f"CVE: {row.get('cve_id', 'N/A')}")
        print(f"Package: {row.get('package_name', 'N/A')} v{row.get('package_version', 'N/A')}")
        print(f"Fixed version: {row.get('fixed_version', 'N/A')}")
        print(f"Source code location: {row.get('source_code_location', 'N/A')}")
        print(f"Path: {row.get('path', 'N/A')} (type: {type(row.get('path'))})")
        print(f"Start line: {row.get('start_line', 'N/A')} (type: {type(row.get('start_line'))})")
        
        if row["fixed_version"] and pd.notna(row["fixed_version"]):
            # if fixed, add recommendation to bump up version
            row_dict['recommendation'] = f"Upgrade {row['package_name']} from existing vulnerable version {row['package_version']} to fixed version {row['fixed_version']}."
            print(f"✅ Recommendation: Upgrade to fixed version")
            
        elif (row["source_code_location"] and pd.notna(row["source_code_location"]) and 
              row['path'] and pd.notna(row['path'])):
            print(f"🔍 Attempting code-based remediation...")
            
            # extract repo name from github url
            repo_name = row["source_code_location"].split("/")[-1]

            # ensure Vuln-Guard organization personal access token is provided in env vars
            if not GH_TOKEN:
                raise ValueError("GH_TOKEN environment variable not set. Cannot authenticate with GitHub CLI. Please set GH_TOKEN to a valid GitHub personal access token with appropriate permissions.")
            
            # rewrite path to have root directory dep_repos_root_dir_path
            file_path = Path(row['path'])
            file_path_parts = file_path.parts
            
            try:
                start_index = file_path_parts.index(repo_name)
                # Reconstruct the path from the repo folder onwards
                portion = Path(*file_path_parts[start_index:])
                path = os.path.join(dep_repos_root_dir_path, str(portion))
                print(f"📁 File path: {path}")
            except ValueError:
                print(f"⚠️  Could not find repo name '{repo_name}' in path '{row['path']}'")
                row_dict['recommendation'] = f"Unable to generate remediation: repo name not found in path."
                output_vulns.append(row_dict)
                continue

            # ✅ Convert values to proper types, handling NaN
            extra_lines = row.get('extra_lines') if pd.notna(row.get('extra_lines')) else None
            start_line = int(row['start_line']) if pd.notna(row.get('start_line')) else None
            start_col = int(row['start_col']) if pd.notna(row.get('start_col')) else None
            start_offset = int(row['start_offset']) if pd.notna(row.get('start_offset')) else None
            end_line = int(row['end_line']) if pd.notna(row.get('end_line')) else None
            end_col = int(row['end_col']) if pd.notna(row.get('end_col')) else None
            end_offset = int(row['end_offset']) if pd.notna(row.get('end_offset')) else None

            print(f"📍 Code location: lines {start_line}-{end_line}, cols {start_col}-{end_col}")

            # extract vulnerable code snippet if available
            code_snippet_dict = _extract_code_snippet(
                path,
                extra_lines,
                start_line,
                start_col,
                start_offset,
                end_line,
                end_col,
                end_offset
            )

            # generate remediation suggestion based on code snippet and other details
            if code_snippet_dict['code_snippet'] and code_snippet_dict['file_contents']:
                print(f"✅ Code snippet extracted successfully")
                # load LLM model
                model, tokenizer = load_llm(model_id, with_quantization=with_quantization)
                # extract code context
                code_snippet_dict = _extract_code_context(model, tokenizer, row, code_snippet_dict)
                # construct prompt for remediation generation
                prompt = _construct_prompt(row, code_snippet_dict)
                # invoke LLM with prompt to get remediation suggestion
                remediation_suggestion = invoke_llm_model(model, tokenizer, prompt)
                row_dict['recommendation'] = remediation_suggestion
                print(f"✅ LLM remediation generated")
                
                # create github issue with remediation suggestion
                try:
                    git_issue_output = run_cmd_and_parse_output([
                        "gh", "issue", "create", 
                        "-R", f"{GITHUB_ORG_NAME}/{repo_name}", 
                        "-t", f"{row['cve_id']} Remediation: {row['summary']}", 
                        "-b", f"{remediation_suggestion}", 
                        "--json", "url", 
                        "--jq", ".url"
                    ])
                    row_dict['remediation_github_url'] = git_issue_output
                    print(f"✅ GitHub issue created: {git_issue_output}")
                except Exception as e:
                    print(f"⚠️  Warning: Could not create GitHub issue for {row['cve_id']}: {e}")
                    row_dict['remediation_github_url'] = None
            else:
                row_dict['recommendation'] = "Unable to generate remediation: code snippet information unavailable."
                print(f"⚠️  Skipping: code snippet info unavailable")
        else:
            row_dict['recommendation'] = "Unable to generate remediation: source code location or path is empty."
            print(f"⚠️  Skipping: source code location or path is empty")

        # ✅ Append the complete row dictionary to output
        output_vulns.append(row_dict)

    # ✅ Create DataFrame from list of dictionaries to preserve all columns
    output_df = pd.DataFrame(output_vulns)
    
    # ✅ Verify all original columns are present
    missing_columns = set(original_columns) - set(output_df.columns)
    if missing_columns:
        print(f"⚠️  WARNING: Missing columns in output: {missing_columns}")
        # Add missing columns with None values
        for col in missing_columns:
            output_df[col] = None
    
    # ✅ Reorder columns to match original order, plus new columns at the end
    new_columns = [col for col in output_df.columns if col not in original_columns]
    final_column_order = original_columns + new_columns
    output_df = output_df[final_column_order]
    
    print(f"\n📋 Output DataFrame has {len(output_df.columns)} columns")
    print(f"   Original columns: {len(original_columns)}")
    print(f"   New columns: {new_columns}")

    # ✅ Save to both formats with error handling
    try:
        output_df.to_parquet(output_pd_path, index=False)
        print(f"✅ Saved remediation results to Parquet: {output_pd_path}")
    except Exception as e:
        print(f"⚠️  Warning: Could not save Parquet file: {e}")
    
    try:
        output_df.to_csv(csv_path, index=False, encoding='utf-8')
        print(f"✅ Saved remediation results to CSV: {csv_path}")
    except Exception as e:
        print(f"⚠️  Warning: Could not save CSV file: {e}")

    return output_df

def _extract_code_snippet(
    path: str,
    extra_lines: Optional[str],
    start_line: Optional[str],
    start_col: Optional[str],
    start_offset: Optional[str],
    end_line: Optional[str],
    end_col: Optional[str],
    end_offset: Optional[str]
) -> Dict[str, str]:
    """
    Extract vulnerable code snippet from cloned git fork file, based on path and position information provided.
    Also store the full file contents.
    """
    code_snippet_dict = {'code_snippet': None, 'file_contents': None}
    print("Starting code snippet extraction...")

    # try to extract code snippet from extra_lines
    if extra_lines:
        code_snippet_dict['code_snippet'] = extra_lines
        print(f"successfully extracted code snippet using extra_lines. Code snippet: {code_snippet_dict['code_snippet']}")

    # if code snippet could not be extracted, use start_offset and end_offset
    if not code_snippet_dict['code_snippet'] and start_offset and end_offset:
        try:
            with open(path, 'rb') as f:  # Open in binary read mode
                f.seek(start_offset)
                snippet_bytes = f.read(end_offset - start_offset)
                code_snippet_dict['code_snippet'] = snippet_bytes.decode('utf-8')  # Decode to string (adjust encoding if needed)
                print(f"successfully extracted code snippet using start_offset and end_offset. Code snippet: {code_snippet_dict['code_snippet']}")
        except FileNotFoundError:
            print(f"Error: File not found at {path}. Could not extract code snippet info.")
            return code_snippet_dict
        except Exception as e:
            print(f"An error occurred while extracting code snippet from start_offset and end_offset: {e}")

    # if code snippet could not be extracted, use start_line, start_col, end_line, and end_col
    if not code_snippet_dict['code_snippet'] and start_line and start_col and end_line and end_col:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # Ensure valid line range
            if start_line < 1 or end_line > len(lines):
                raise ValueError("Line numbers are out of range.")

            # Convert to 0-based for Python indexing
            start_line_idx = start_line - 1
            end_line_idx = end_line - 1

            # Single-line case
            if start_line == end_line:
                return lines[start_line_idx][start_col - 1:end_col]

            # Multi-line case
            extracted_lines = [lines[start_line_idx][start_col - 1:]]  # start line (partial)
            extracted_lines.extend(lines[start_line_idx + 1:end_line_idx])  # full middle lines
            extracted_lines.append(lines[end_line_idx][:end_col])  # end line (partial)

            code_snippet_dict['code_snippet'] = ''.join(extracted_lines)
            print(f"successfully extracted code snippet using start_line, start_col, end_line, and end_offset.")
        except Exception as e:
            print(f"An error occurred while extracting code snippet from start_line, start_col, end_line, and end_col: {e}")

    # store full file contents in dict
    try:
        with open(path, 'r', encoding='utf-8') as f:
            code_snippet_dict['file_contents'] = f.read()
            print(f"successfully extracted code file contents.")
    except Exception as e:
         print(f"An error occurred while extracting full file contents: {e}")
        
    return code_snippet_dict

def _extract_code_context(
    model, 
    tokenizer, 
    row: pd.Series,
    code_snippet_dict: Dict[str, str]) -> Dict[str, str]:
    """
    Use LLM to extract code context corresponding to vulnerable code snippet and file contents.
    """
    if code_snippet_dict:
        code_extract_prompt = _construct_extract_code_context_prompt(row, code_snippet_dict)
        # invoke LLM to extract code context
        code_snippet_dict['code_context'] = invoke_llm_model(model, tokenizer, code_extract_prompt)
    return code_snippet_dict

def _construct_extract_code_context_prompt(row: pd.Series, code_snippet_dict: Dict[str, str]) -> str:
    """
    Construct LLM prompt for code context extraction.
    """
    code_extract_prompt = f"""
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
    - Vulnerable code file contents:
    ```
    {code_snippet_info['code_context']}
    ```

    Evaluate the vulnerable code snippet based on the supplementary vulnerability
    and code information.

    Here is the vulnerable code snippet:
    ```
    {code_snippet_info['code_snippet']}
    ```

   Output only the generated code remediation. Use the 'Extra message' as a hint for what fix to make.
   Provide only the valid patched code. Do not include additional text in your response.

    Patched code:
    ```
    """
    return prompt