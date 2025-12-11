import pandas as pd

df = pd.read_parquet("artifacts/identify/react_semgrep_results_df.parquet")
print(df[['cve_id', 'path', 'start_line']].head())