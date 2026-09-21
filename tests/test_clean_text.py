"""Clean-input contract: benign text must pass every validator untouched.

Each built-in validator should be silent on harmless input — no findings, no
redaction, ``passed`` True, and the returned text byte-for-byte identical to the
input. These are the "do no harm" tests that catch over-eager patterns.
"""
import pytest

from bulwark import (
    Guard,
    InjectionValidator,
    JSONSchemaValidator,
    PIIValidator,
    SecretsValidator,
    ToxicityValidator,
)

# Inputs with nothing for a text-scanning validator to catch: the empty string,
# whitespace-only, and ordinary prose free of PII / secrets / injections / slurs.
CLEAN_TEXTS = [
    "",
    "   \n\t  ",
    "The quick brown fox jumps over the lazy dog near the river.",
    "Thanks for your help earlier; the report looks great to me.",
]

# Validators whose notion of "clean" is arbitrary natural-language text. The
# JSONSchemaValidator is excluded here because plain prose is *not* valid JSON —
# it is exercised separately below with well-formed JSON.
TEXT_VALIDATOR_FACTORIES = [
    PIIValidator,
    InjectionValidator,
    SecretsValidator,
    ToxicityValidator,
]


@pytest.mark.parametrize("factory", TEXT_VALIDATOR_FACTORIES)
@pytest.mark.parametrize("text", CLEAN_TEXTS)
def test_clean_text_produces_no_findings(factory, text):
    assert factory().check(text) == []


@pytest.mark.parametrize("factory", TEXT_VALIDATOR_FACTORIES)
@pytest.mark.parametrize("text", CLEAN_TEXTS)
def test_clean_text_passes_guard_unchanged(factory, text):
    r = Guard([factory()]).check(text)
    assert r.passed
    assert not r.blocked
    assert not r.redacted
    assert r.text == text
    assert r.findings == []
    assert bool(r) is True


@pytest.mark.parametrize("text", CLEAN_TEXTS)
def test_clean_text_passes_full_pipeline(text):
    # The whole built-in stack (minus JSON schema) leaves benign text alone.
    g = Guard([
        PIIValidator(),
        InjectionValidator(),
        SecretsValidator(),
        ToxicityValidator(),
    ])
    r = g.check(text)
    assert r.passed
    assert r.text == text
    assert r.findings == []


@pytest.mark.parametrize("text", [
    '{"ok": true}',
    '{"name": "Ada", "age": 36}',
    '[1, 2, 3]',
    '"just a json string"',
])
def test_valid_json_passes_schemaless_validator_unchanged(text):
    # For JSONSchemaValidator, "clean" means well-formed JSON. With no schema
    # supplied it only checks parseability, so valid JSON must pass untouched.
    r = Guard([JSONSchemaValidator()]).check(text)
    assert r.passed
    assert not r.blocked
    assert not r.redacted
    assert r.text == text
    assert r.findings == []
