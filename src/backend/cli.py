from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional
from utils.compat import model_to_dict

import typer
from workflow.vuln_assess.assessor import assess_vulns
from schemas.models import VulnScan, VulnAssessment
from workflow.vuln_detect.detector import detect_vulns
from workflow.vuln_assess.assessor import (
    assess_vulns_df,
    assess_vulns_df_and_save,
)
from workflow.vuln_remediate.remediator import remediate_vulns
from utils.df import findings_to_df

app = typer.Typer(
    add_completion=True,
    help="VulnGuard CLI — detect, assess, and remediate software vulnerabilities.",
)

# ---------- utility IO ----------

def _read_json_list(path: Path) -> list:
    data = json.loads(path.read_text())
    if isinstance(data, dict) and "findings" in data:
        data = data["findings"]
    if not isinstance(data, list):
        raise typer.BadParameter(f"Expected a list in {path}")
    return data

def _write_json(obj, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2))

# ---------- commands ----------

@app.command()
def detect(
    repo_url: str = typer.Option(..., "--repo-url", "-r", help="Repository URL or path."),
    out: Path = typer.Option(Path("artifacts/detect/findings.json"), "--out", "-o"),
):
    """
    Run detector and save raw findings (VulnScan[]) to JSON.
    """
    # extract repo name from URL for dir_path
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    findings: List[VulnScan] = detect_vulns(repo_url, dir_path=f"artifacts/detect/{repo_name}", sbom_path=f"artifacts/detect/{repo_name}_sbom.spdx.json", output_raw_scan_path=f"artifacts/detect/{repo_name}_scan.json", output_final_scan_path=f"artifacts/detect/{repo_name}_scan.parquet")
    payload = [model_to_dict(f) for f in findings]
    _write_json(payload, out)
    typer.echo(f"✅ wrote {out} with {len(payload)} findings")

@app.command()
def assess(
    infile: Path = typer.Option(..., "--in", "-i", help="JSON file with VulnScan[] or {findings:[...]}."),
    out_dir: Path = typer.Option(Path("artifacts/assessments"), "--out-dir"),
    save: bool = typer.Option(True, "--save/--no-save", help="Persist CSV/Parquet to disk."),
    print_head: int = typer.Option(10, "--head", help="Print first N rows."),
):
    """
    Assess findings (KEV/EPSS/risk). Optionally save CSV/Parquet.
    """
    scans = [VulnScan(**x) for x in _read_json_list(infile)]
    assessed_models = assess_vulns(scans)

    # persist CSV/Parquet via DF helpers, if requested
    if save:
        _, artifacts = assess_vulns_df_and_save(scans, out_dir=str(out_dir))
    else:
        artifacts = {}

    # write assessments as list[dict]
    out_json = out_dir / "assessed.json"
    _write_json([model_to_dict(a) for a in assessed_models], out_json)

@app.command()
def remediate(
    infile: Path = typer.Option(..., "--in", "-i", help="JSON VulnAssessment[] (from assess step)."),
    out: Path = typer.Option(Path("artifacts/remediations/recommendations.json"), "--out", "-o"),
):
    """
    Generate remediation recommendations from assessed findings.
    """
    items = [VulnAssessment(**x) for x in _read_json_list(infile)]
    recs = remediate_vulns(items)
    _write_json([model_to_dict(r) for r in recs], out)
    typer.echo(f"🔧 wrote {out} with {len(recs)} recommendations")

@app.command()
def pipeline(
    repo_url: str = typer.Option(..., "--repo-url", "-r"),
    out_dir: Path = typer.Option(Path("artifacts"), "--out-dir"),
):
    """
    End-to-end: detect → assess (save CSV/Parquet) → remediate.
    """
    detect_out = out_dir / "detect/findings.json"
    assess_dir = out_dir / "assessments"
    remediate_out = out_dir / "remediations/recommendations.json"

    # detect
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    findings = detect_vulns(repo_url, dir_path=f"artifacts/detect/{repo_name}", sbom_path=f"artifacts/detect/{repo_name}_sbom.spdx.json", output_raw_scan_path=f"artifacts/detect/{repo_name}_scan.json", output_final_scan_path=f"artifacts/detect/{repo_name}_scan.parquet")
    _write_json([model_to_dict(f) for f in findings], detect_out)
    typer.echo(f"🧭 detect → {detect_out}")

    # assess (+ save artifacts)
    df, art = assess_vulns_df_and_save(findings, out_dir=str(assess_dir))
    typer.echo(f"📊 assess → {art}")

    # remediate
    from schemas.models import VulnAssessment  # local import to avoid cycles
    assessed = [VulnAssessment(**row) for row in df.to_dict(orient="records")]
    recs = remediate_vulns(assessed)
    _write_json([r.model_dump() for r in recs], remediate_out)
    typer.echo(f"🔧 remediate → {remediate_out}")

def main():
    app()  # required if you enable console_scripts entry point

if __name__ == "__main__":
    main()
