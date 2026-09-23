"""Shared pytest fixtures: ready-made Guards used across the test suite.

Fixtures are function-scoped (the default) so a test can freely mutate a Guard
(e.g. ``add`` a validator) without leaking state into the next test.
"""
import pytest

from bulwark import (
    Guard,
    InjectionValidator,
    PIIValidator,
    SecretsValidator,
)


@pytest.fixture
def pii_guard():
    """A Guard with only the PII validator (redact mode)."""
    return Guard([PIIValidator()])


@pytest.fixture
def injection_guard():
    """A Guard with only the prompt-injection validator (block mode)."""
    return Guard([InjectionValidator()])


@pytest.fixture
def full_guard():
    """A three-layer pipeline: PII + injection + secrets."""
    return Guard([PIIValidator(), InjectionValidator(), SecretsValidator()])
