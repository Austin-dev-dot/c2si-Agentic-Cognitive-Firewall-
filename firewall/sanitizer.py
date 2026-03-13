import re


# delimiters attackers use to inject fake system/user turns
DANGEROUS_DELIMITERS = [
    r"```(\w*)",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"\[INST\]",
    r"\[/INST\]",
    r"<\|system\|>",
    r"<\|user\|>",
    r"<\|assistant\|>",
    r"###\s*System:",
    r"###\s*Instruction:",
]

INJECTION_PHRASES = [
    r"ignore all previous instructions",
    r"disregard all previous instructions",
    r"forget your previous instructions",
    r"you are now a",
    r"act as a",
    r"print your system prompt",
    r"reveal your instructions",
]


def sanitize_text(text: str) -> str:
    """strips known injection delimiters and phrases from the input"""
    if not text:
        return text

    sanitized = text

    for delim in DANGEROUS_DELIMITERS:
        sanitized = re.sub(delim, " [REMOVED_DELIMITER] ", sanitized, flags=re.IGNORECASE)

    for phrase in INJECTION_PHRASES:
        sanitized = re.sub(phrase, " [REMOVED_INSTRUCTION] ", sanitized, flags=re.IGNORECASE)

    # clean up repeated special chars (obfuscation attempts)
    sanitized = re.sub(r"([^a-zA-Z0-9\s]){10,}", r"\1[REMOVED_REPEAT]", sanitized)
    sanitized = re.sub(r"\s+", " ", sanitized).strip()

    return sanitized
