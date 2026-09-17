"""The Guard: run a pipeline of validators over text and aggregate the result.

Redaction is applied by the Guard (not the validators) so that overlapping
spans and ordering are handled in exactly one place.
"""
from __future__ import annotations

from .result import Action, Finding, GuardResult
from .validators.base import Validator


class Guard:
    """Compose validators into a single guardrail pipeline.

    >>> from bulwark import Guard, PIIValidator
    >>> g = Guard([PIIValidator()])
    >>> g.check("mail me at a@b.com").text
    'mail me at [REDACTED_EMAIL]'
    """

    def __init__(self, validators: list[Validator] | None = None) -> None:
        self.validators: list[Validator] = list(validators or [])

    def add(self, validator: Validator) -> "Guard":
        self.validators.append(validator)
        return self

    def check(self, text: str) -> GuardResult:
        findings: list[Finding] = []
        for v in self.validators:
            findings.extend(v.check(text))
        redacted = _apply_redactions(text, findings)
        return GuardResult(text=redacted, original=text, findings=findings)

    def __call__(self, text: str) -> GuardResult:
        return self.check(text)


def _apply_redactions(text: str, findings: list[Finding]) -> str:
    """Replace REDACT spans with their placeholders, right-to-left so earlier
    offsets stay valid. Overlapping redactions are collapsed (widest wins)."""
    spans = [
        (f.span[0], f.span[1], f.replacement or "[REDACTED]")
        for f in findings
        if f.action is Action.REDACT and f.span is not None
    ]
    if not spans:
        return text
    # Sort by start; drop spans fully contained in an already-kept one.
    spans.sort(key=lambda s: (s[0], -(s[1])))
    kept: list[tuple[int, int, str]] = []
    last_end = -1
    for start, end, repl in spans:
        if start >= last_end:
            kept.append((start, end, repl))
            last_end = end
    out = text
    for start, end, repl in sorted(kept, key=lambda s: s[0], reverse=True):
        out = out[:start] + repl + out[end:]
    return out
