"""Subclass ``Validator`` to add a project-specific guardrail.

The five built-in validators cover the common cases (PII, injection, secrets,
schema, toxicity), but most real deployments have at least one rule that's
specific to them: banned phrases, disallowed claims, internal codenames that
shouldn't leak. A custom validator is just a class with a ``name`` and a
``check(text) -> list[Finding]`` method, same contract as every built-in one,
so it composes into a ``Guard`` exactly like the rest.

This one blocks a configurable list of exact phrases (case-insensitive, whole
word/phrase boundaries so it won't fire mid-word), the kind of thing you'd use
for "never say we guarantee returns" in a fintech assistant or "never mention
the unreleased codename" internally.

Run it with:

    python examples/custom_validator.py
"""
from __future__ import annotations

import re

from bulwark import Action, Finding, Guard, PIIValidator, Severity, Validator


class BannedPhraseValidator(Validator):
    """Blocks a fixed list of exact phrases, case-insensitive.

    Each match is reported as its own :class:`Finding` with the phrase
    itself in ``meta``, so callers can tell which rule fired without
    re-parsing the message.
    """

    name = "banned_phrase"

    def __init__(self, phrases: list[str], severity: Severity = Severity.HIGH) -> None:
        if not phrases:
            raise ValueError("BannedPhraseValidator needs at least one phrase")
        self.phrases = list(phrases)
        self.severity = severity
        # whole-word/phrase boundaries, same approach as ToxicityValidator,
        # so "guarantees" doesn't trip a rule written for "guarantee".
        self._patterns = [
            (phrase, re.compile(rf"(?<!\w){re.escape(phrase)}(?!\w)", re.I))
            for phrase in self.phrases
        ]

    def check(self, text: str) -> list[Finding]:
        findings = []
        for phrase, pattern in self._patterns:
            for m in pattern.finditer(text):
                findings.append(Finding(
                    validator=self.name,
                    action=Action.BLOCK,
                    message=f"banned phrase: {phrase!r}",
                    severity=self.severity,
                    span=(m.start(), m.end()),
                    meta={"phrase": phrase},
                ))
        return findings


def main() -> None:
    guard = Guard([
        BannedPhraseValidator(["guaranteed returns", "risk-free investment"]),
        PIIValidator(),
    ])

    # 1) Clean text passes, and composes with a built-in validator unchanged.
    clean = "Past performance doesn't predict future results. Contact jane@corp.com for details."
    result = guard.check(clean)
    print("--- clean text ---")
    print(result.text)
    assert result.passed
    assert "[REDACTED_EMAIL]" in result.text

    # 2) The custom rule blocks on its own, same as any built-in validator.
    risky = "This fund offers guaranteed returns of 12% annually."
    result = guard.check(risky)
    print("\n--- banned phrase ---")
    print([f.message for f in result.findings])
    assert result.blocked
    assert result.findings[0].validator == "banned_phrase"

    # 3) Two matches in one message both get reported.
    both = "It's a risk-free investment with guaranteed returns."
    result = guard.check(both)
    print("\n--- two banned phrases in one message ---")
    print([f.meta["phrase"] for f in result.findings])
    assert len(result.findings) == 2


if __name__ == "__main__":
    main()
