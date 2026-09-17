"""Validator base class."""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..result import Finding


class Validator(ABC):
    """A single guardrail. Given text, return zero or more findings.

    Validators are pure and stateless with respect to a single ``check`` call:
    they never mutate the input. Redaction is expressed *declaratively* via a
    finding's ``span`` + ``replacement``; the Guard applies the transform.
    """

    #: stable, snake_case identifier used in findings and configs
    name: str = "validator"

    @abstractmethod
    def check(self, text: str) -> list[Finding]:
        ...

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"<{type(self).__name__} name={self.name!r}>"
