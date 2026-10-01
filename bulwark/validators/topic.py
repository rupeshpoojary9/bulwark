"""Topic allow/deny lists: block output that touches configured subjects."""
from __future__ import annotations

import re

from ..result import Action, Finding, Severity
from .base import Validator


def _compile(terms: list[str]) -> list[tuple[str, re.Pattern]]:
    # Whole-word/phrase boundaries, same approach as ToxicityValidator, so a
    # term like "law" doesn't fire inside "lawn" or "flaw".
    return [
        (term, re.compile(rf"(?<!\w){re.escape(term)}(?!\w)", re.I))
        for term in terms
    ]


class TopicValidator(Validator):
    """Blocks text that matches a denylist of topics, or (in allow mode)
    blocks text that matches none of an allowlist.

    Exactly one of ``deny`` or ``allow`` must be set. Each is a mapping of
    topic label to a list of keywords/phrases for that topic, so a finding
    carries which topic fired, not just that something did.

    >>> v = TopicValidator(deny={"medical_advice": ["take ibuprofen", "see a doctor"]})
    >>> v.check("You should see a doctor about that.")[0].meta["topic"]
    'medical_advice'
    """

    name = "topic"

    def __init__(
        self,
        deny: dict[str, list[str]] | None = None,
        allow: dict[str, list[str]] | None = None,
        severity: Severity = Severity.MEDIUM,
    ) -> None:
        if bool(deny) == bool(allow):
            raise ValueError("TopicValidator needs exactly one of deny or allow")
        self.mode = "deny" if deny else "allow"
        topics = deny if deny else allow
        self._topics = {
            topic: _compile(terms) for topic, terms in topics.items()
        }
        self.severity = severity

    def check(self, text: str) -> list[Finding]:
        matches: list[Finding] = []
        for topic, patterns in self._topics.items():
            for term, pattern in patterns:
                m = pattern.search(text)
                if m:
                    matches.append(Finding(
                        validator=self.name, action=Action.BLOCK,
                        message=f"{self.mode}listed topic matched: {topic!r} ({term!r})",
                        severity=self.severity, span=(m.start(), m.end()),
                        meta={"topic": topic, "term": term},
                    ))
                    break  # one finding per topic is enough

        if self.mode == "deny":
            return matches

        # Allow mode: block only if NONE of the allowed topics matched.
        if matches:
            return []
        return [Finding(
            validator=self.name, action=Action.BLOCK,
            message="text does not match any allowlisted topic",
            severity=self.severity, meta={"topics": list(self._topics)},
        )]
