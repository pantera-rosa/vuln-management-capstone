from fastapi import APIRouter

from src.backend.schemas.models import AssessRequest, AssessResponse
from src.backend.workflow.vuln_detect.vuln_scan import detect_vulns
from src.backend.workflow.vuln_assess.assessor import (
    assess_vulns,
    assess_vulns_df_and_save,
)

# TODO: REMEDIATION NOT YET IMPLEMENTED
# from src.backend.workflow.vuln_remediate.remediator import remediate_vulns
from fastapi import APIRouter, Query


api_router = APIRouter()


@api_router.get("/health")
def health():
    return {"status": "ok"}


@api_router.post("/v1/vuln/detect")
def detect(req: dict):
    repo_url = req.get("repo_url", "")
    findings = detect_vulns(repo_url)
    return {"repo_url": repo_url, "findings": [f.dict() for f in findings]}


@api_router.post("/v1/vuln/assess", response_model=AssessResponse)
def assess(req: AssessRequest, save: bool = Query(False)):
    assessed = assess_vulns(req.findings)
    artifacts = None
    if save:
        # Re-run through the DF path to persist (tiny overhead, but simple)
        _, artifacts = assess_vulns_df_and_save(req.findings)
    return AssessResponse(findings=assessed, artifacts=artifacts)


# @api_router.post("/v1/vuln/remediate")
# def remediate(req: dict):
#     rems = remediate_vulns(req.get("findings", []))
#     return {"remediations": [r.dict() for r in rems]}
