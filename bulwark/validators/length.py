"""Output length bounds: flag text outside a configured character or word count."""
from __future__ import annotations

from ..result import Action, Finding, Severity
from .base import Validator


class LengthValidator(Validator):
    """Flags output shorter or longer than configured bounds.

    Catches two real failure modes: a truncated or empty response (too short)
    and a runaway or repeating generation (too long). Character bounds and
    word bounds can be set independently; either can be left as ``None`` to
    skip that check. Word count is a plain whitespace split, not a tokenizer,
    so it is a rough proxy, not an exact token budget.
    """

    name = "length"

    def __init__(
        self,
        min_chars: int | None = None,
        max_chars: int | None = None,
        min_words: int | None = None,
        max_words: int | None = None,
        action: Action = Action.BLOCK,
    ) -> None:
        if all(v is None for v in (min_chars, max_chars, min_words, max_words)):
            raise ValueError("LengthValidator needs at least one bound set")
        self.min_chars = min_chars
        self.max_chars = max_chars
        self.min_words = min_words
        self.max_words = max_words
        self.action = action

    def check(self, text: str) -> list[Finding]:
        n_chars = len(text)
        n_words = len(text.split())

        if self.min_chars is not None and n_chars < self.min_chars:
            return [self._finding(
                f"text is {n_chars} characters, below the minimum of {self.min_chars}",
                meta={"n_chars": n_chars, "bound": "min_chars", "limit": self.min_chars},
            )]
        if self.max_chars is not None and n_chars > self.max_chars:
            return [self._finding(
                f"text is {n_chars} characters, above the maximum of {self.max_chars}",
                meta={"n_chars": n_chars, "bound": "max_chars", "limit": self.max_chars},
            )]
        if self.min_words is not None and n_words < self.min_words:
            return [self._finding(
                f"text is {n_words} words, below the minimum of {self.min_words}",
                meta={"n_words": n_words, "bound": "min_words", "limit": self.min_words},
            )]
        if self.max_words is not None and n_words > self.max_words:
            return [self._finding(
                f"text is {n_words} words, above the maximum of {self.max_words}",
                meta={"n_words": n_words, "bound": "max_words", "limit": self.max_words},
            )]
        return []

    def _finding(self, message: str, meta: dict) -> Finding:
        return Finding(
            validator=self.name, action=self.action, message=message,
            severity=Severity.LOW, meta=meta,
        )
