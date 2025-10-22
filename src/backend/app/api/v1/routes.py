from fastapi import APIRouter

from schemas.models import AssessRequest, AssessResponse
from workflow.vuln_detect.detector import detect_vulns
from workflow.vuln_assess.assessor import assess_vulns
from workflow.vuln_remediate.remediator import remediate_vulns
from fastapi import APIRouter, Query
from schemas.models import AssessRequest, AssessResponse
from workflow.vuln_assess.assessor import assess_vulns, assess_vulns_df_and_save


api_router = APIRouter()

@api_router.get("/health")
def health():
    return {"status": "ok"}

@api_router.post("/v1/vuln/detect")
def detect(req: dict):
    repo_url = req.get("repo_url", "")
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    findings = detect_vulns(repo_url, dir_path=f"artifacts/detect/{repo_name}", sbom_path=f"artifacts/detect/{repo_name}_sbom.spdx.json", output_raw_scan_path=f"artifacts/detect/{repo_name}_scan.json", output_final_scan_path=f"artifacts/detect/{repo_name}_scan.parquet")
    return {"repo_url": repo_url, "findings": [f.dict() for f in findings]}

@api_router.post("/v1/vuln/assess", response_model=AssessResponse)
def assess(req: AssessRequest, save: bool = Query(False)):
    assessed = assess_vulns(req.findings)
    artifacts = None
    if save:
        # Re-run through the DF path to persist (tiny overhead, but simple)
        _, artifacts = assess_vulns_df_and_save(req.findings)
    return AssessResponse(findings=assessed, artifacts=artifacts)

@api_router.post("/v1/vuln/remediate")
def remediate(req: dict):
    rems = remediate_vulns(req.get("findings", []))
    return {"remediations": [r.dict() for r in rems]}
