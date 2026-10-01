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
# 2-letter country + 2-digit check + 11-30 alphanumeric, the ISO 13616 shape.
# Actual length is country-specific; the mod-97 check below is the real
# filter, this regex only needs to be loose enough to catch candidates.
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[ ]?[A-Z0-9]{0,3}\b")
# Deliberately conservative, common formats only: 1-2 letters + 6-7 digits
# (e.g. India, UK), 9 digits, or 1 letter + 8 digits (e.g. US). Can't cover
# every country's format, and some plain alphanumeric codes will still match
# by coincidence, hence the LOW severity rather than HIGH.
_PASSPORT = re.compile(r"(?<![A-Za-z0-9])(?:[A-Z]{1,2}\d{6,7}|\d{9}|[A-Z]\d{8})(?![A-Za-z0-9])")


def _luhn_ok(digits: str) -> bool:
    """Luhn checksum, filters random digit runs from real card numbers."""
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


def _iban_ok(candidate: str) -> bool:
    """ISO 7064 mod-97-10 checksum — filters random alphanumeric runs from
    real IBANs. Country-specific length isn't checked; the checksum is."""
    s = candidate.replace(" ", "").upper()
    if not (15 <= len(s) <= 34):
        return False
    rearranged = s[4:] + s[:4]
    try:
        digits = "".join(str(int(ch, 36)) for ch in rearranged)
    except ValueError:
        return False
    return int(digits) % 97 == 1


class PIIValidator(Validator):
    """Flags and (by default) redacts common personally-identifiable data.

    >>> PIIValidator().check("mail me at a@b.com")[0].meta["kind"]
    'email'
    """

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
        findings += self._find(
            text, _IBAN, "iban", "[REDACTED_IBAN]", Severity.HIGH,
            validate=_iban_ok,
        )
        findings += self._find(text, _PASSPORT, "passport", "[REDACTED_PASSPORT]",
                               Severity.LOW)
        return findings
