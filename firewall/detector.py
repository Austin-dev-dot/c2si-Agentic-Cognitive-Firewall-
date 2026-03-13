import re
from dataclasses import dataclass, field


# known injection patterns — each has a regex and a severity weight (0-1)
INJECTION_PATTERNS: list[dict] = [
    {
        "label": "instruction_override",
        "pattern": re.compile(
            r"(ignore|disregard|forget|override|bypass)\s+"
            r"(all\s+)?(previous|prior|above|earlier|initial)\s+"
            r"(instructions?|prompts?|rules?|context|directions?)",
            re.IGNORECASE,
        ),
        "severity": 1.0,
    },
    {
        "label": "role_hijack",
        "pattern": re.compile(
            r"(you\s+are\s+now|act\s+as|pretend\s+to\s+be|"
            r"assume\s+the\s+role\s+of|switch\s+to|become)\s+",
            re.IGNORECASE,
        ),
        "severity": 0.85,
    },
    {
        "label": "system_prompt_leak",
        "pattern": re.compile(
            r"(show|reveal|display|print|output|repeat|echo)\s+"
            r"(your\s+)?(system\s+prompt|initial\s+instructions?|"
            r"hidden\s+instructions?|system\s+message|original\s+prompt)",
            re.IGNORECASE,
        ),
        "severity": 0.95,
    },
    {
        "label": "delimiter_injection",
        "pattern": re.compile(
            r"(```|<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|"
            r"<\|system\|>|<\|user\|>|<\|assistant\|>|###\s*system)",
            re.IGNORECASE,
        ),
        "severity": 0.9,
    },
    {
        "label": "data_exfiltration",
        "pattern": re.compile(
            r"(send|transmit|post|upload|exfiltrate|forward)\s+"
            r"(the\s+)?(data|information|credentials|keys?|tokens?|"
            r"passwords?|secrets?)\s+(to|via|through|using)",
            re.IGNORECASE,
        ),
        "severity": 1.0,
    },
    {
        "label": "encoding_evasion",
        "pattern": re.compile(
            r"(base64|hex|rot13|url.?encode|unicode|ascii)\s*"
            r"(decode|encode|convert|translate)",
            re.IGNORECASE,
        ),
        "severity": 0.7,
    },
]


def _heuristic_score(text: str) -> float:
    """score based on statistical anomalies common in injection attempts"""
    score = 0.0

    if len(text) > 1500:
        score += 0.3

    # high ratio of special characters
    special = sum(1 for c in text if not c.isalnum() and not c.isspace())
    if len(text) > 0 and (special / len(text)) > 0.25:
        score += 0.25

    if text.count("\n") > 8:
        score += 0.2

    if re.search(r"https?://", text):
        score += 0.15

    # lots of commanding verbs = suspicious
    imperatives = len(re.findall(
        r"\b(do|must|always|never|execute|run|call|send|write|delete|drop)\b",
        text, re.IGNORECASE,
    ))
    if imperatives > 5:
        score += 0.2

    return min(score, 1.0)


@dataclass
class DetectionResult:
    is_injection: bool = False
    matched_patterns: list[str] = field(default_factory=list)
    pattern_score: float = 0.0
    heuristic_score: float = 0.0
    combined_score: float = 0.0

    @property
    def risk_level(self) -> str:
        if self.combined_score >= 0.8:
            return "CRITICAL"
        if self.combined_score >= 0.5:
            return "HIGH"
        if self.combined_score >= 0.3:
            return "MEDIUM"
        return "LOW"


def detect_injection(text: str, threshold: float = 0.5) -> DetectionResult:
    """run the full detection pipeline on a piece of text"""
    result = DetectionResult()

    # phase 1: regex pattern matching
    max_severity = 0.0
    for entry in INJECTION_PATTERNS:
        if entry["pattern"].search(text):
            result.matched_patterns.append(entry["label"])
            max_severity = max(max_severity, entry["severity"])

    result.pattern_score = max_severity

    # phase 2: heuristic scoring
    result.heuristic_score = _heuristic_score(text)

    # combine — pattern match dominates, heuristic adds context
    if result.pattern_score > 0:
        result.combined_score = min(
            result.pattern_score * 0.7 + result.heuristic_score * 0.3, 1.0
        )
    else:
        result.combined_score = result.heuristic_score * 0.6

    result.is_injection = result.combined_score >= threshold
    return result
