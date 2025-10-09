from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, Iterable, List
from datetime import datetime
import importlib.util
import pandas as pd
from utils.compat import model_to_dict

def findings_to_df(items: Iterable[Any]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for it in items:
        rows.append(model_to_dict(it))
    return pd.DataFrame(rows)


def save_assessment_frames(df: pd.DataFrame, out_dir: str = "artifacts/assessments", stem: str | None = None) -> Dict[str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ts = stem or datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    paths: Dict[str, str] = {}
    csv_path = out / f"assessment_{ts}.csv"
    df.to_csv(csv_path, index=False)                     # pandas to_csv :contentReference[oaicite:6]{index=6}
    paths["csv"] = str(csv_path)

    have_pyarrow = importlib.util.find_spec("pyarrow") is not None
    have_fastparquet = importlib.util.find_spec("fastparquet") is not None
    if have_pyarrow or have_fastparquet:
        pq_path = out / f"assessment_{ts}.parquet"
        df.to_parquet(pq_path, index=False)              # requires pyarrow/fastparquet :contentReference[oaicite:7]{index=7}
        paths["parquet"] = str(pq_path)

    if "risk_label" in df.columns:
        by_label = (
            df["risk_label"].value_counts()
              .rename_axis("risk_label")
              .reset_index(name="count")
        )
        lbl_csv = out / f"summary_by_label_{ts}.csv"
        by_label.to_csv(lbl_csv, index=False)
        paths["summary_by_label_csv"] = str(lbl_csv)

    return paths
