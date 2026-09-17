"""Core result types shared by every validator and the Guard."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Action(str, Enum):
    """What a validator wants done about a finding."""
    ALLOW = "allow"      # informational only
    REDACT = "redact"    # transform the text (mask the span)
    BLOCK = "block"      # reject the whole payload


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Finding:
    """One issue found in a piece of text."""
    validator: str
    action: Action
    message: str
    severity: Severity = Severity.MEDIUM
    span: Optional[tuple[int, int]] = None   # (start, end) into the *original* text
    replacement: Optional[str] = None        # placeholder to mask a REDACT span
    meta: dict = field(default_factory=dict)


@dataclass
class GuardResult:
    """Aggregate outcome of running a Guard over some text."""
    text: str                 # possibly redacted text
    original: str             # the untouched input
    findings: list[Finding] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return any(f.action is Action.BLOCK for f in self.findings)

    @property
    def passed(self) -> bool:
        return not self.blocked

    @property
    def redacted(self) -> bool:
        return self.text != self.original

    def by_validator(self, name: str) -> list[Finding]:
        return [f for f in self.findings if f.validator == name]

    def __bool__(self) -> bool:  # `if result:` == "is it safe to use"
        return self.passed
