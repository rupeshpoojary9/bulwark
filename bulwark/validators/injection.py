"""Heuristic prompt-injection / jailbreak detection.

Rule-based on purpose: it is fast, dependency-free, explainable, and gives the
eval harness a transparent baseline to beat. Each hit carries the pattern that
fired so false positives are debuggable.
"""
from __future__ import annotations

import re

from ..result import Action, Finding, Severity
from .base import Validator

# (regex, human label). Ordered roughly by how strong a signal each is.
_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"ignore (all|any|the)?\s*(previous|prior|above|earlier)\s+"
                r"(instructions|prompts?|rules|directions)", re.I),
     "ignore-previous-instructions"),
    (re.compile(r"disregard (all|any|the)?\s*(previous|prior|above)?\s*"
                r"(instructions|rules|context)", re.I),
     "disregard-instructions"),
    (re.compile(r"forget (everything|all|what).{0,20}(said|instructed|above)", re.I),
     "forget-context"),
    (re.compile(r"\b(reveal|print|show|repeat|leak)\b.{0,30}"
                r"(system|initial|hidden|original)\s+prompt", re.I),
     "exfiltrate-system-prompt"),
    (re.compile(r"you are (now|no longer)\b", re.I), "role-override"),
    (re.compile(r"\bDAN\b|do anything now", re.I), "dan-jailbreak"),
    (re.compile(r"developer mode|jailbreak", re.I), "jailbreak-keyword"),
    (re.compile(r"pretend (to be|you are|that you)", re.I), "roleplay-override"),
    (re.compile(r"act as (an?|the)\b.{0,40}(no|without).{0,20}"
                r"(restrictions|filter|rules|guidelines)", re.I),
     "unrestricted-persona"),
    (re.compile(r"\bsudo\b|\broot\b.{0,15}access", re.I), "privilege-escalation"),
    (re.compile(r"end of (prompt|instructions).{0,20}(new|now)", re.I),
     "delimiter-injection"),
]


class InjectionValidator(Validator):
    """Blocks text that looks like an attempt to override the system prompt."""

    name = "prompt_injection"

    def __init__(self, block: bool = True) -> None:
        self.action = Action.BLOCK if block else Action.ALLOW

    def check(self, text: str) -> list[Finding]:
        findings = []
        for pattern, label in _PATTERNS:
            m = pattern.search(text)
            if m:
                findings.append(Finding(
                    validator=self.name, action=self.action,
                    message=f"possible prompt injection ({label})",
                    severity=Severity.HIGH, span=(m.start(), m.end()),
                    meta={"pattern": label, "match": m.group()},
                ))
        return findings
