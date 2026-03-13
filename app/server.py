from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path

from firewall.detector import detect_injection
from firewall.sanitizer import sanitize_text
from firewall.policy import PolicyEngine
from firewall.risk import evaluate_risk

app = FastAPI(
    title="Cognitive Firewall API",
    version="0.1.0"
)

# load policies on startup
policy_engine = PolicyEngine()
policy_path = Path(__file__).parent.parent / "policies" / "default.yaml"
if policy_path.exists():
    policy_engine.load_from_file(policy_path)
    print(f"loaded {len(policy_engine.rules)} policy rules")


class ScanRequest(BaseModel):
    content: str
    context_type: str = "user_prompt"


class ScanResponse(BaseModel):
    action: str
    risk_score: float
    reasons: list[str]
    sanitized_content: str | None = None


@app.get("/health")
def health_check():
    return {"status": "healthy", "version": "0.1.0"}


@app.post("/scan", response_model=ScanResponse)
def scan_content(request: ScanRequest):
    detection = detect_injection(request.content)
    triggered_policies = policy_engine.evaluate(request.content)
    assessment = evaluate_risk(request.content, detection, triggered_policies)

    sanitized_content = None
    if assessment.action == "SANITIZE":
        sanitized_content = sanitize_text(request.content)
        if not sanitized_content.strip():
            assessment.action = "BLOCK"
            assessment.reasons.append("sanitization resulted in empty content")

    return ScanResponse(
        action=assessment.action,
        risk_score=assessment.score,
        reasons=assessment.reasons,
        sanitized_content=sanitized_content
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.server:app", host="0.0.0.0", port=8000, reload=True)
