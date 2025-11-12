# df.py
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, Iterable
from datetime import datetime
import importlib.util
import os

import pandas as pd
from src.backend.utils.compat import model_to_dict

# --- New: small helper to detect Lambda ---
def _default_outdir() -> str:
    # When running in Lambda, only /tmp is writable.
    # Elsewhere, keep the existing local default.
    if os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
        return os.getenv("ASSESS_OUTDIR", "/tmp/assessments")
    return os.getenv("ASSESS_OUTDIR", "artifacts/assessments")

#def findings_to_df(items: Iterable[Any]) -> pd.DataFrame:
#    rows: List[Dict[str, Any]] = [model_to_dict(it) for it in items]
#    return pd.DataFrame(rows)

def findings_to_df(items: Iterable[Any]) -> pd.DataFrame:
    return pd.DataFrame([item.model_dump() for item in items])

def save_assessment_frames(
    df: pd.DataFrame, out_dir: str | None = None, stem: str | None = None, gzip_csv: bool = False
) -> Dict[str, str]:
    """
    Save assessment DataFrame to CSV (and Parquet if available) plus a summary_by_label CSV.
    Returns a dict of local file paths.
    """
    out_dir = out_dir or _default_outdir()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ts = stem or datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    paths: Dict[str, str] = {}

    # CSV (optionally compressed to reduce S3 upload size)
    csv_path = out / (f"assessment_{ts}.csv.gz" if gzip_csv else f"assessment_{ts}.csv")
    df.to_csv(csv_path, index=False, compression="gzip" if gzip_csv else None)
    paths["csv"] = str(csv_path)

    # Parquet (only if an engine is present)
    have_pyarrow = importlib.util.find_spec("pyarrow") is not None
    have_fastparquet = importlib.util.find_spec("fastparquet") is not None
    if have_pyarrow or have_fastparquet:
        pq_path = out / f"assessment_{ts}.parquet"
        df.to_parquet(pq_path, index=False)
        paths["parquet"] = str(pq_path)

    # Optional label summary
    if "risk_label" in df.columns:
        by_label = (
            df["risk_label"].value_counts().rename_axis("risk_label").reset_index(name="count")
        )
        lbl_csv = out / f"summary_by_label_{ts}.csv"
        by_label.to_csv(lbl_csv, index=False)
        paths["summary_by_label_csv"] = str(lbl_csv)

    return paths

# --- New: convenience wrapper to upload directly to S3 after writing locally ---
def save_and_upload_assessment_frames(
    df: pd.DataFrame,
    bucket: str,
    prefix: str,
    out_dir: str | None = None,
    stem: str | None = None,
    gzip_csv: bool = False,
) -> Dict[str, str]:
    """
    Writes artifacts locally (defaulting to /tmp in Lambda), uploads to S3, and returns S3 URIs.
    """
    import boto3  # local import to avoid hard dep where not needed
    s3 = boto3.client("s3")

    local_paths = save_assessment_frames(df, out_dir=out_dir, stem=stem, gzip_csv=gzip_csv)
    s3_uris: Dict[str, str] = {}
    for key, p in local_paths.items():
        filename = Path(p).name
        s3_key = f"{prefix.rstrip('/')}/{filename}"
        # upload_file handles multipart for large files
        s3.upload_file(p, bucket, s3_key)  # boto3 S3 client upload_file usage
        s3_uris[key] = f"s3://{bucket}/{s3_key}"
    return s3_uris
def append_df(output_df, df_to_append):
    if output_df is None:
        output_df = df_to_append
    else:
        output_df = pd.concat([output_df, df_to_append], ignore_index=True)
    return output_df
