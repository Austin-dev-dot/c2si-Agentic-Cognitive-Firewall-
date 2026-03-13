from dataclasses import dataclass
from typing import Literal

from .detector import DetectionResult
from .policy import PolicyRule


@dataclass
class RiskAssessment:
    action: Literal["ALLOW", "SANITIZE", "BLOCK"]
    score: float  # 0.0 (safe) to 1.0 (malicious)
    reasons: list[str]


def evaluate_risk(
    text: str,
    detection: DetectionResult,
    triggered_policies: list[PolicyRule]
) -> RiskAssessment:
    reasons = []
    score = 0.0

    # detection signals
    if detection.pattern_score > 0:
        score += detection.pattern_score * 0.6
        reasons.append(f"Detected injection patterns: {', '.join(detection.matched_patterns)}")

    if detection.heuristic_score > 0.5:
        score += detection.heuristic_score * 0.4
        reasons.append("High heuristic anomaly score")

    # policy violations
    for policy in triggered_policies:
        if policy.action == "BLOCK":
            score = 1.0
            reasons.append(f"Policy '{policy.name}': BLOCK")
            break
        elif policy.action == "SANITIZE":
            score = max(score, 0.4)
            reasons.append(f"Policy '{policy.name}': needs sanitization")

    score = min(score, 1.0)

    # final verdict
    if score >= 0.7 or any(p.action == "BLOCK" for p in triggered_policies):
        action = "BLOCK"
    elif score >= 0.3 or any(p.action == "SANITIZE" for p in triggered_policies):
        action = "SANITIZE"
    else:
        action = "ALLOW"

    return RiskAssessment(action=action, score=round(score, 2), reasons=reasons)
