"""Detect leaked credentials / API keys in text (input or model output)."""
from __future__ import annotations

import re

from ..result import Action, Finding, Severity
from .base import Validator

# (regex, label). Kept specific to keep the false-positive rate low.
_SECRETS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws_access_key_id"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "openai_api_key"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "github_token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "slack_token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "private_key"),
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "google_api_key"),
]


class SecretsValidator(Validator):
    """Flags API keys / tokens; blocks by default (credential leakage is high-risk)."""

    name = "secrets"

    def __init__(self, block: bool = True) -> None:
        self.action = Action.BLOCK if block else Action.REDACT

    def check(self, text: str) -> list[Finding]:
        findings = []
        for pattern, label in _SECRETS:
            for m in pattern.finditer(text):
                findings.append(Finding(
                    validator=self.name, action=self.action,
                    message=f"credential detected ({label})",
                    severity=Severity.HIGH, span=(m.start(), m.end()),
                    replacement=f"[REDACTED_{label.upper()}]",
                    meta={"kind": label},
                ))
        return findings
