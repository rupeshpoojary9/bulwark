"""Validate that model output is well-formed JSON matching a given JSON Schema.

The single most common structured-output guardrail: the model was asked for
JSON, so prove it actually returned JSON of the right shape before you trust it.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from ..result import Action, Finding, Severity
from .base import Validator

try:  # jsonschema is optional; schema-shape checks degrade gracefully without it
    import jsonschema
    _HAVE_JSONSCHEMA = True
except ImportError:  # pragma: no cover
    _HAVE_JSONSCHEMA = False


class JSONSchemaValidator(Validator):
    """BLOCK when output is not valid JSON, or does not match ``schema``."""

    name = "json_schema"

    def __init__(self, schema: Optional[dict[str, Any]] = None) -> None:
        self.schema = schema

    def check(self, text: str) -> list[Finding]:
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError) as e:
            return [Finding(
                validator=self.name, action=Action.BLOCK,
                message=f"output is not valid JSON: {e}",
                severity=Severity.HIGH, meta={"error": "json_decode"},
            )]

        if self.schema is None:
            return []
        if not _HAVE_JSONSCHEMA:  # pragma: no cover
            return []
        try:
            jsonschema.validate(parsed, self.schema)
        except jsonschema.ValidationError as e:
            return [Finding(
                validator=self.name, action=Action.BLOCK,
                message=f"output does not match schema: {e.message}",
                severity=Severity.HIGH,
                meta={"error": "schema_mismatch", "path": list(e.absolute_path)},
            )]
        return []
