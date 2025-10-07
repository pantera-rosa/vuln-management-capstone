from fastapi import APIRouter

from schemas.models import AssessRequest, AssessResponse
from workflow.vuln_detect.detector import detect_vulns
from workflow.vuln_assess.assessor import assess_vulns
from workflow.vuln_remediate.remediator import remediate_vulns

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
def assess(req: AssessRequest):
    assessed = assess_vulns(req.findings)
    return AssessResponse(findings=assessed)

@api_router.post("/v1/vuln/remediate")
def remediate(req: dict):
    rems = remediate_vulns(req.get("findings", []))
    return {"remediations": [r.dict() for r in rems]}
