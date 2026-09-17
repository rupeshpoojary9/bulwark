"""PII detection + redaction: emails, phone numbers, credit cards, SSNs, IPs."""
from __future__ import annotations

import re

from ..result import Action, Finding, Severity
from .base import Validator

_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
# North-American style phone numbers, tolerant of separators / country code.
_PHONE = re.compile(
    r"(?<!\d)(?:\+?\d{1,2}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)"
)
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_IPV4 = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
# 13-19 digit runs, optionally split by spaces/hyphens (candidate card numbers).
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def _luhn_ok(digits: str) -> bool:
    """Luhn checksum — filters random digit runs from real card numbers."""
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


class PIIValidator(Validator):
    """Flags and (by default) redacts common personally-identifiable data."""

    name = "pii"

    def __init__(self, redact: bool = True) -> None:
        # REDACT masks the span in place; BLOCK rejects the whole payload.
        self.action = Action.REDACT if redact else Action.BLOCK

    def _find(self, text, pattern, label, replacement, sev=Severity.MEDIUM,
              validate=None) -> list[Finding]:
        out = []
        for m in pattern.finditer(text):
            if validate and not validate(m.group()):
                continue
            out.append(Finding(
                validator=self.name, action=self.action,
                message=f"{label} detected", severity=sev,
                span=(m.start(), m.end()), replacement=replacement,
                meta={"kind": label},
            ))
        return out

    def check(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._find(text, _EMAIL, "email", "[REDACTED_EMAIL]")
        findings += self._find(text, _SSN, "ssn", "[REDACTED_SSN]", Severity.HIGH)
        findings += self._find(
            text, _CARD, "credit_card", "[REDACTED_CARD]", Severity.HIGH,
            validate=lambda s: _luhn_ok(re.sub(r"\D", "", s)),
        )
        findings += self._find(text, _PHONE, "phone", "[REDACTED_PHONE]")
        findings += self._find(text, _IPV4, "ip_address", "[REDACTED_IP]",
                               Severity.LOW)
        return findings
