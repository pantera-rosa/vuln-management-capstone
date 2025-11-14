"""
Enhanced Vulnerability Remediation with Reachability Analysis

This module extends the remediation workflow to prioritize and generate
remediation strategies based on reachability analysis results.

Key Enhancements:
1. Prioritization by reachability level (Direct > Indirect > Unknown > Unreachable)
2. Reachability-aware remediation strategies
3. Context-rich LLM prompts with reachability information
4. Detailed remediation reports with prioritization
"""

from __future__ import annotations
import pandas as pd
from typing import Optional, Dict, List, Tuple
import os
import re
from pathlib import Path
from dotenv import load_dotenv

from src.backend.utils.cmd import run_cmd_and_parse_output, run_cmd
from src.backend.utils.df import save_df
from src.backend.utils.llm import load_llm, invoke_llm_model

load_dotenv()

GH_TOKEN = os.environ.get("GH_TOKEN", "")
GITHUB_ORG_NAME = "Vuln-Guard"

# Reachability level priority mapping (higher = more urgent)
REACHABILITY_PRIORITY = {
    'direct': 4,
    'indirect': 3,
    'unknown': 2,
    'unreachable': 1
}


def extract_reachability_from_rationale(rationale: str) -> Tuple[str, float, float]:
    """
    Extract reachability information from assessment rationale string.
    
    Args:
        rationale: Assessment rationale containing reachability info
        
    Returns:
        Tuple of (reachability_level, reachability_score, confidence)
    """
    if not rationale or not isinstance(rationale, str):
        return 'unknown', 0.0, 0.0
    
    # Extract reachability level
    level_match = re.search(r'Reachability:\s*(\w+)', rationale, re.IGNORECASE)
    reachability_level = level_match.group(1).lower() if level_match else 'unknown'
    
    # Extract reachability score
    score_match = re.search(r'score:\s*([\d.]+)', rationale)
    reachability_score = float(score_match.group(1)) if score_match else 0.0
    
    # Extract confidence
    confidence_match = re.search(r'confidence:\s*([\d.]+)', rationale)
    confidence = float(confidence_match.group(1)) if confidence_match else 0.0
    
    return reachability_level, reachability_score, confidence


def prioritize_vulnerabilities(vuln_df: pd.DataFrame) -> pd.DataFrame:
    """
    Prioritize vulnerabilities based on reachability and risk score.
    
    Priority order:
    1. Reachability level (Direct > Indirect > Unknown > Unreachable)
    2. Risk score (within same reachability level)
    3. CVSS score (tie-breaker)
    
    Args:
        vuln_df: DataFrame with vulnerability assessments
        
    Returns:
        Sorted DataFrame with priority column added
    """
    # Extract reachability information from rationale
    if 'rationale' in vuln_df.columns:
        reachability_info = vuln_df['rationale'].apply(extract_reachability_from_rationale)
        vuln_df['reachability_level'] = reachability_info.apply(lambda x: x[0])
        vuln_df['reachability_score'] = reachability_info.apply(lambda x: x[1])
        vuln_df['reachability_confidence'] = reachability_info.apply(lambda x: x[2])
    else:
        vuln_df['reachability_level'] = 'unknown'
        vuln_df['reachability_score'] = 0.0
        vuln_df['reachability_confidence'] = 0.0
    
    # Map reachability level to priority number
    vuln_df['reachability_priority'] = vuln_df['reachability_level'].map(REACHABILITY_PRIORITY)
    vuln_df['reachability_priority'] = vuln_df['reachability_priority'].fillna(2)  # unknown = 2
    
    # Get CVSS score for tie-breaking
    cvss_cols = ['cvss_v3_base_score', 'cvss_v4_base_score', 'cvss_v2_base_score']
    vuln_df['cvss_for_sort'] = 0.0
    for col in cvss_cols:
        if col in vuln_df.columns:
            vuln_df['cvss_for_sort'] = vuln_df['cvss_for_sort'].fillna(0) + vuln_df[col].fillna(0)
            break
    
    # Sort by priority
    sorted_df = vuln_df.sort_values(
        by=['reachability_priority', 'risk_score', 'cvss_for_sort'],
        ascending=[False, False, False]
    ).reset_index(drop=True)
    
    # Add overall priority rank
    sorted_df['remediation_priority'] = range(1, len(sorted_df) + 1)
    
    return sorted_df


def generate_reachability_aware_recommendation(row: pd.Series) -> str:
    """
    Generate recommendation text based on reachability level.
    
    Args:
        row: Vulnerability data row
        
    Returns:
        Recommendation text
    """
    reachability_level = row.get('reachability_level', 'unknown')
    package_name = row['package_name']
    package_version = row['package_version']
    fixed_version = row.get('fixed_version')
    risk_label = row.get('risk_label', 'UNKNOWN')
    
    # Base recommendation based on whether fix is available
    if fixed_version:
        base_rec = f"Upgrade {package_name} from {package_version} to {fixed_version}"
    else:
        base_rec = f"Apply code-level fix for {package_name} {package_version}"
    
    # Add reachability-specific guidance
    if reachability_level == 'direct':
        return (
            f"🚨 URGENT: {base_rec}. "
            f"This {risk_label} vulnerability is DIRECTLY REACHABLE from your application code. "
            f"The vulnerable code path has been confirmed through dataflow analysis. "
            f"Immediate remediation is required to prevent exploitation."
        )
    elif reachability_level == 'indirect':
        return (
            f"⚠️  HIGH PRIORITY: {base_rec}. "
            f"This {risk_label} vulnerability is INDIRECTLY REACHABLE through your application's call chain. "
            f"While not directly called, the vulnerable code can be reached through intermediate functions. "
            f"Schedule remediation in the current sprint."
        )
    elif reachability_level == 'unreachable':
        return (
            f"📝 LOW PRIORITY: {base_rec}. "
            f"This {risk_label} vulnerability appears to be UNREACHABLE from your application code. "
            f"No dataflow path was found from application entry points to the vulnerable code. "
            f"Consider scheduling for a future release or documenting as accepted risk."
        )
    else:  # unknown
        return (
            f"🔍 INVESTIGATE: {base_rec}. "
            f"Reachability for this {risk_label} vulnerability could not be determined with certainty. "
            f"Manual investigation recommended to confirm exploitability before prioritizing remediation."
        )


def construct_reachability_aware_prompt(row: pd.Series, code_snippet_info: Dict[str, str]) -> str:
    """
    Construct LLM prompt with reachability context for better remediation.
    
    Args:
        row: Vulnerability data
        code_snippet_info: Code snippet and context
        
    Returns:
        Enhanced prompt string
    """
    reachability_level = row.get('reachability_level', 'unknown')
    reachability_score = row.get('reachability_score', 0.0)
    reachability_confidence = row.get('reachability_confidence', 0.0)
    dataflow_exists = 'complete' in str(row.get('rationale', '')).lower()
    
    # Reachability context for the LLM
    reachability_context = _generate_reachability_context(
        reachability_level,
        reachability_score,
        reachability_confidence,
        dataflow_exists
    )
    
    # Dataflow information if available
    dataflow_info = ""
    if row.get('extra_dataflow_trace_taint_source'):
        dataflow_info = f"""
    Dataflow Analysis:
    - Taint Source: {row.get('extra_dataflow_trace_taint_source', 'N/A')}
    - Intermediate Variables: {row.get('extra_dataflow_trace_intermediate_vars', 'N/A')}
    - Taint Sink: {row.get('extra_dataflow_trace_taint_sink', 'N/A')}
        """
    
    prompt = f"""
    Your task is to generate a secure code fix for a vulnerability with confirmed or suspected reachability.
    
    REACHABILITY ANALYSIS:
    {reachability_context}
    {dataflow_info}
    
    VULNERABILITY INFORMATION:
    - CVE ID: {row['cve_id']}
    - GHSA ID: {row['ghsa_id']}
    - CWE ID: {row['cwe_id']}
    - CWE Name: {row.get('cwe_name', 'N/A')}
    - Risk Level: {row.get('risk_label', 'N/A')} (Score: {row.get('risk_score', 'N/A')})
    - Summary: {row['summary']}
    - Description: {row['description']}
    
    CODE CONTEXT:
    - Language: {row['language']}
    - File: {row.get('filename', 'N/A')}
    - Path: {row.get('path', 'N/A')}
    - Vulnerability Details: {row.get('extra_message', 'N/A')}
    
    VULNERABLE CODE CONTEXT:
    ```{row['language']}
    {code_snippet_info.get('code_context', code_snippet_info.get('file_contents', ''))}
    ```
    
    VULNERABLE CODE SNIPPET:
    ```{row['language']}
    {code_snippet_info['code_snippet']}
    ```
    
    REMEDIATION INSTRUCTIONS:
    Given the reachability analysis showing this vulnerability is {reachability_level}, 
    generate a secure code fix that:
    1. Addresses the specific vulnerability type ({row.get('cwe_id', 'unknown CWE')})
    2. Prevents exploitation through the identified dataflow path (if applicable)
    3. Maintains existing functionality while eliminating the vulnerability
    4. Follows secure coding best practices for {row['language']}
    
    Output ONLY the patched code. Do not include explanations or markdown formatting.
    
    PATCHED CODE:
    ```{row['language']}
    """
    
    return prompt


def _generate_reachability_context(
    level: str,
    score: float,
    confidence: float,
    dataflow_exists: bool
) -> str:
    """Generate human-readable reachability context for LLM prompt."""
    
    level_descriptions = {
        'direct': (
            "⚠️  CRITICAL PRIORITY - DIRECT REACHABILITY\n"
            "    This vulnerability is DIRECTLY reachable from application code.\n"
            "    Attack vectors can exploit this through normal application usage.\n"
            "    A complete dataflow path exists from user input to the vulnerable code."
        ),
        'indirect': (
            "⚠️  HIGH PRIORITY - INDIRECT REACHABILITY\n"
            "    This vulnerability is INDIRECTLY reachable through your application's call chain.\n"
            "    While not directly invoked, the vulnerable code can be triggered through intermediate functions.\n"
            "    Careful analysis is needed to prevent exploitation."
        ),
        'unreachable': (
            "ℹ️  LOW PRIORITY - UNREACHABLE\n"
            "    This vulnerability appears unreachable from application entry points.\n"
            "    No dataflow path was identified from user input to the vulnerable code.\n"
            "    However, apply defense-in-depth principles in your fix."
        ),
        'unknown': (
            "❓ UNKNOWN REACHABILITY\n"
            "    Reachability could not be conclusively determined.\n"
            "    Assume vulnerability is exploitable and apply comprehensive fix."
        )
    }
    
    context = level_descriptions.get(level, level_descriptions['unknown'])
    context += f"\n    - Reachability Score: {score:.1f}/100"
    context += f"\n    - Analysis Confidence: {confidence:.2f}"
    context += f"\n    - Complete Dataflow Path: {'Yes' if dataflow_exists else 'No'}"
    
    return context


def generate_remediation_with_reachability(
    vuln_df: pd.DataFrame,
    model_id: str,
    output_pd_path: str,
    dep_repos_root_dir_path: str,
    with_quantization: bool = False,
    max_remediations: Optional[int] = None,
    only_reachable: bool = False
) -> Tuple[pd.DataFrame, Dict[str, str]]:
    """
    Enhanced remediation generation with reachability-aware prioritization.
    
    Args:
        vuln_df: DataFrame with vulnerability assessments including reachability info
        model_id: LLM model ID for code generation
        output_pd_path: Path to save remediation results
        dep_repos_root_dir_path: Root directory for cloned repositories
        with_quantization: Whether to use 4-bit quantization for LLM
        max_remediations: Optional limit on number of remediations to generate
        only_reachable: If True, only remediate direct/indirect reachable vulnerabilities
        
    Returns:
        Tuple of (DataFrame with remediations, dict with output paths)
    """
    # Skip if output already exists
    if os.path.isfile(output_pd_path) and os.path.getsize(output_pd_path) > 0:
        print(f"Remediation file {output_pd_path} already exists. Skipping.")
        df = pd.read_parquet(output_pd_path)
        csv_path = output_pd_path.replace('.parquet', '.csv')
        paths = {
            'parquet': output_pd_path,
            'csv': csv_path if os.path.exists(csv_path) else None
        }
        return df, paths
    
    print("\n" + "="*80)
    print("REACHABILITY-AWARE VULNERABILITY REMEDIATION")
    print("="*80 + "\n")
    
    # Step 1: Prioritize vulnerabilities by reachability
    print("📊 Prioritizing vulnerabilities by reachability...")
    prioritized_df = prioritize_vulnerabilities(vuln_df.copy())
    
    # Print prioritization summary
    print("\nPrioritization Summary:")
    for level in ['direct', 'indirect', 'unknown', 'unreachable']:
        count = (prioritized_df['reachability_level'] == level).sum()
        if count > 0:
            emoji = {'direct': '🚨', 'indirect': '⚠️ ', 'unknown': '🔍', 'unreachable': '📝'}
            print(f"  {emoji.get(level, '•')} {level.upper()}: {count} vulnerabilities")
    
    # Step 2: Filter if needed
    if only_reachable:
        print("\n🎯 Filtering to only DIRECT and INDIRECT reachable vulnerabilities...")
        prioritized_df = prioritized_df[
            prioritized_df['reachability_level'].isin(['direct', 'indirect'])
        ]
        print(f"   Remediation scope: {len(prioritized_df)} vulnerabilities")
    
    if max_remediations:
        print(f"\n📌 Limiting to top {max_remediations} highest priority vulnerabilities...")
        prioritized_df = prioritized_df.head(max_remediations)
    
    # Step 3: Generate remediations with reachability context
    print(f"\n🔧 Generating remediation strategies for {len(prioritized_df)} vulnerabilities...")
    print("-" * 80)
    
    output_vulns = []
    model = None
    tokenizer = None
    
    for idx, row in prioritized_df.iterrows():
        print(f"\n[{idx + 1}/{len(prioritized_df)}] Processing: {row['cve_id']} - {row['package_name']}")
        print(f"   Reachability: {row['reachability_level'].upper()} | Risk: {row['risk_label']}")
        
        # Generate basic recommendation based on reachability
        row['recommendation'] = generate_reachability_aware_recommendation(row)
        
        # For fixed versions, just recommend upgrade
        if row["fixed_version"]:
            print(f"   ✅ Fix available: Upgrade to {row['fixed_version']}")
            output_vulns.append(row)
            continue
        
        # For unfixed vulnerabilities with code location, generate code fix
        if row["source_code_location"] and row.get('path'):
            try:
                repo_name = row["source_code_location"].split("/")[-1]
                
                # Validate GH_TOKEN
                if not GH_TOKEN:
                    print("   ⚠️  Warning: GH_TOKEN not set, skipping GitHub integration")
                    output_vulns.append(row)
                    continue
                
                # Reconstruct file path
                file_path = Path(row['path'])
                file_path_parts = file_path.parts
                if repo_name in file_path_parts:
                    start_index = file_path_parts.index(repo_name)
                    portion = Path(*file_path_parts[start_index:])
                    path = os.path.join(dep_repos_root_dir_path, str(portion))
                else:
                    print(f"   ⚠️  Warning: Cannot locate file path for {repo_name}")
                    output_vulns.append(row)
                    continue
                
                # Extract code snippet
                code_snippet_dict = _extract_code_snippet(
                    path,
                    row.get('extra_lines'),
                    row.get('start_line'),
                    row.get('start_col'),
                    row.get('start_offset'),
                    row.get('end_line'),
                    row.get('end_col'),
                    row.get('end_offset')
                )
                
                if code_snippet_dict['code_snippet'] and code_snippet_dict['file_contents']:
                    # Lazy load LLM (only when needed for code generation)
                    if model is None:
                        print("\n   🤖 Loading LLM for code generation...")
                        model, tokenizer = load_llm(model_id, with_quantization=with_quantization)
                    
                    # Extract code context
                    print("   📝 Extracting code context...")
                    code_snippet_dict = _extract_code_context(model, tokenizer, row, code_snippet_dict)
                    
                    # Construct reachability-aware prompt
                    print("   🎯 Generating reachability-aware code fix...")
                    prompt = construct_reachability_aware_prompt(row, code_snippet_dict)
                    
                    # Generate remediation
                    remediation_suggestion = invoke_llm_model(model, tokenizer, prompt)
                    row['recommendation'] = remediation_suggestion
                    
                    # Create GitHub issue with reachability priority
                    priority_label = f"reachability:{row['reachability_level']}"
                    issue_title = f"[{row['risk_label']}] {row['cve_id']}: {row['summary']}"
                    issue_body = f"""
## Reachability Analysis
- **Level**: {row['reachability_level'].upper()}
- **Score**: {row['reachability_score']:.1f}/100
- **Confidence**: {row['reachability_confidence']:.2f}

## Vulnerability Details
{row['recommendation']}

## Suggested Code Fix
```{row['language']}
{remediation_suggestion}
```
                    """
                    
                    try:
                        run_cmd(["gh", "repo", "edit", f"{GITHUB_ORG_NAME}/{repo_name}", "--enable-issues"])
                        git_issue_output = run_cmd_and_parse_output(
                            ["gh", "issue", "create", "-R", f"{GITHUB_ORG_NAME}/{repo_name}",
                             "-t", issue_title, "-b", issue_body, "-l", priority_label],
                            return_dict=False
                        )
                        row['remediation_github_url'] = git_issue_output
                        print(f"   ✅ GitHub issue created: {git_issue_output}")
                    except Exception as e:
                        print(f"   ⚠️  Warning: Could not create GitHub issue: {e}")
                else:
                    print(f"   ⚠️  Skipping: Code snippet unavailable")
                    
            except Exception as e:
                print(f"   ❌ Error processing {row['cve_id']}: {e}")
        else:
            print(f"   ⚠️  Skipping: No source code location or path")
        
        output_vulns.append(row)
    
    # Step 4: Create output DataFrame
    output_df = pd.DataFrame(output_vulns)
    
    # Step 5: Generate remediation report
    print("\n" + "="*80)
    print("REMEDIATION SUMMARY")
    print("="*80)
    _print_remediation_summary(output_df)
    
    # Step 6: Save results in both formats (CSV and Parquet)
    save_df(output_df, output_pd_path)
    
    # Also save as CSV
    csv_path = output_pd_path.replace('.parquet', '.csv')
    output_df.to_csv(csv_path, index=False)
    
    # Create paths dictionary
    paths = {
        'parquet': output_pd_path,
        'csv': csv_path
    }
    
    print(f"\n✅ Remediation results saved to:")
    print(f"   - Parquet: {output_pd_path}")
    print(f"   - CSV: {csv_path}")
    
    return output_df, paths


def _print_remediation_summary(df: pd.DataFrame):
    """Print a summary of remediation results."""
    
    total = len(df)
    with_fix = df['fixed_version'].notna().sum()
    with_code_fix = df['recommendation'].notna().sum()
    with_github = df['remediation_github_url'].notna().sum() if 'remediation_github_url' in df.columns else 0
    
    print(f"\nTotal Vulnerabilities: {total}")
    print(f"  • With Version Fix Available: {with_fix}")
    print(f"  • With Code Remediation: {with_code_fix}")
    print(f"  • GitHub Issues Created: {with_github}")
    
    print("\nBy Reachability Level:")
    for level in ['direct', 'indirect', 'unknown', 'unreachable']:
        count = (df.get('reachability_level', 'unknown') == level).sum()
        if count > 0:
            emoji = {'direct': '🚨', 'indirect': '⚠️ ', 'unknown': '🔍', 'unreachable': '📝'}
            print(f"  {emoji.get(level, '•')} {level.upper()}: {count}")
    
    print("\nBy Risk Level:")
    if 'risk_label' in df.columns:
        for risk in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = (df['risk_label'] == risk).sum()
            if count > 0:
                print(f"  • {risk}: {count}")


# Helper functions from original generate_remediation.py

def _extract_code_snippet(
    path: str,
    extra_lines: Optional[str],
    start_line: Optional[float],
    start_col: Optional[float],
    start_offset: Optional[float],
    end_line: Optional[float],
    end_col: Optional[float],
    end_offset: Optional[float]
) -> Dict[str, str]:
    """Extract vulnerable code snippet from file."""
    code_snippet_dict = {'code_snippet': None, 'file_contents': None}
    
    # Try extra_lines first
    if extra_lines:
        code_snippet_dict['code_snippet'] = extra_lines
        
    # Try offset-based extraction
    if not code_snippet_dict['code_snippet'] and start_offset is not None and end_offset is not None:
        try:
            with open(path, 'rb') as f:
                f.seek(int(start_offset))
                snippet_bytes = f.read(int(end_offset) - int(start_offset))
                code_snippet_dict['code_snippet'] = snippet_bytes.decode('utf-8')
        except Exception as e:
            print(f"      Warning: Offset extraction failed: {e}")
    
    # Try line/column-based extraction
    if not code_snippet_dict['code_snippet'] and all(x is not None for x in [start_line, start_col, end_line, end_col]):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            start_line, end_line = int(start_line), int(end_line)
            start_col, end_col = int(start_col), int(end_col)
            
            if start_line == end_line:
                code_snippet_dict['code_snippet'] = lines[start_line - 1][start_col - 1:end_col]
            else:
                extracted = [lines[start_line - 1][start_col - 1:]]
                extracted.extend(lines[start_line:end_line - 1])
                extracted.append(lines[end_line - 1][:end_col])
                code_snippet_dict['code_snippet'] = ''.join(extracted)
        except Exception as e:
            print(f"      Warning: Line/col extraction failed: {e}")
    
    # Extract full file contents
    try:
        with open(path, 'r', encoding='utf-8') as f:
            code_snippet_dict['file_contents'] = f.read()
    except Exception as e:
        print(f"      Warning: Could not read file contents: {e}")
    
    return code_snippet_dict


def _extract_code_context(
    model, 
    tokenizer, 
    row: pd.Series,
    code_snippet_dict: Dict[str, str]
) -> Dict[str, str]:
    """Use LLM to extract relevant code context."""
    if code_snippet_dict and code_snippet_dict.get('file_contents'):
        prompt = f"""
Extract the {row['language']} code that is relevant to this vulnerability.
Focus on the vulnerable code path and any related functions or classes.

File contents:
```
{code_snippet_dict['file_contents']}
```

Vulnerable snippet:
```
{code_snippet_dict['code_snippet']}
```

Provide only the extracted relevant {row['language']} code:
```
"""
        code_snippet_dict['code_context'] = invoke_llm_model(model, tokenizer, prompt)
    return code_snippet_dict


# Backward compatibility: alias to new function
generate_remediation = generate_remediation_with_reachability