import yaml
from pathlib import Path
from dataclasses import dataclass, field
import re


@dataclass
class PolicyRule:
    name: str
    match_pattern: str
    action: str  # ALLOW, SANITIZE, BLOCK
    description: str = ""


@dataclass
class PolicyEngine:
    rules: list[PolicyRule] = field(default_factory=list)

    def load_from_file(self, file_path: str | Path) -> None:
        path = Path(file_path)
        if not path.exists():
            return

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        for r in data.get("rules", []):
            self.rules.append(
                PolicyRule(
                    name=r.get("name", "unnamed_rule"),
                    match_pattern=r.get("match", ""),
                    action=str(r.get("action", "ALLOW")).upper(),
                    description=r.get("description", ""),
                )
            )

    def evaluate(self, text: str) -> list[PolicyRule]:
        """check text against all loaded rules, return the ones that matched"""
        triggered = []
        for rule in self.rules:
            if not rule.match_pattern:
                continue
            if re.search(rule.match_pattern, text, re.IGNORECASE):
                triggered.append(rule)
        return triggered
