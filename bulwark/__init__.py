"""bulwark — a local-first LLM guardrails toolkit.

Wrap any LLM call with a layered defense (PII redaction, prompt-injection
detection, secret-leak detection, structured-output validation) and measure
each guardrail against a labeled dataset.
"""
from .guard import Guard
from .result import Action, Finding, GuardResult, Severity
from .validators import (
    InjectionValidator,
    JSONSchemaValidator,
    PIIValidator,
    SecretsValidator,
    Validator,
)

__version__ = "0.1.0"

__all__ = [
    "Guard",
    "GuardResult",
    "Finding",
    "Action",
    "Severity",
    "Validator",
    "PIIValidator",
    "InjectionValidator",
    "SecretsValidator",
    "JSONSchemaValidator",
]
