"""Lexicon-based toxicity detection.

A transparent, dependency-free baseline: match a curated lexicon of abusive
terms as whole words (case-insensitive) and flag by category. Like the other
built-in validators it is explainable and gives the eval harness a baseline to
beat with a learned classifier later. The lexicon is intentionally small and
extensible via the ``extra_terms`` argument.
"""
from __future__ import annotations

import re

from ..result import Action, Finding, Severity
from .base import Validator

# term -> (category, severity). Threats rate HIGH; profanity/insults MEDIUM.
# Deliberately excludes slurs; extend via ``extra_terms`` for your policy.
_LEXICON: dict[str, tuple[str, Severity]] = {
    # threats / violence
    "kill you": ("threat", Severity.HIGH),
    "kill yourself": ("threat", Severity.HIGH),
    "i will hurt you": ("threat", Severity.HIGH),
    "beat you up": ("threat", Severity.HIGH),
    "burn down": ("threat", Severity.HIGH),
    # insults
    "idiot": ("insult", Severity.MEDIUM),
    "stupid": ("insult", Severity.MEDIUM),
    "moron": ("insult", Severity.MEDIUM),
    "loser": ("insult", Severity.MEDIUM),
    "shut up": ("insult", Severity.MEDIUM),
    "worthless": ("insult", Severity.MEDIUM),
    "pathetic": ("insult", Severity.MEDIUM),
    # profanity
    "damn": ("profanity", Severity.LOW),
    "crap": ("profanity", Severity.LOW),
    "bastard": ("profanity", Severity.MEDIUM),
}


def _compile(terms: dict[str, tuple[str, Severity]]) -> list[tuple[re.Pattern, str, str, Severity]]:
    out = []
    for term, (category, severity) in terms.items():
        # whole-word match so "class" never trips on "ass", etc.
        pattern = re.compile(rf"(?<!\w){re.escape(term)}(?!\w)", re.I)
        out.append((pattern, term, category, severity))
    return out


class ToxicityValidator(Validator):
    """Flags abusive language via a curated lexicon; blocks by default."""

    name = "toxicity"

    def __init__(self, block: bool = True,
                 extra_terms: dict[str, tuple[str, Severity]] | None = None) -> None:
        self.action = Action.BLOCK if block else Action.REDACT
        lexicon = dict(_LEXICON)
        if extra_terms:
            lexicon.update(extra_terms)
        self._patterns = _compile(lexicon)

    def check(self, text: str) -> list[Finding]:
        findings = []
        for pattern, term, category, severity in self._patterns:
            for m in pattern.finditer(text):
                findings.append(Finding(
                    validator=self.name, action=self.action,
                    message=f"toxic language ({category}): {term!r}",
                    severity=severity, span=(m.start(), m.end()),
                    replacement="[REDACTED_TOXIC]",
                    meta={"category": category, "term": term},
                ))
        return findings
