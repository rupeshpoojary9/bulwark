import pytest

from bulwark import (
    Guard,
    JSONSchemaValidator,
    SecretsValidator,
)


@pytest.mark.parametrize("text,kind", [
    ("key AKIAIOSFODNN7EXAMPLE here", "aws_access_key_id"),
    ("token ghp_" + "a" * 36, "github_token"),
    ("use sk-" + "b" * 32, "openai_api_key"),
])
def test_secret_blocked(text, kind):
    r = Guard([SecretsValidator()]).check(text)
    assert r.blocked
    assert r.findings[0].meta["kind"] == kind


def test_secret_redact_mode():
    r = Guard([SecretsValidator(block=False)]).check("sk-" + "c" * 32)
    assert r.passed
    assert "[REDACTED_OPENAI_API_KEY]" in r.text


def test_no_secret_passes():
    assert Guard([SecretsValidator()]).check("just a normal sentence").passed


def test_schema_rejects_non_json():
    r = Guard([JSONSchemaValidator()]).check("not json at all")
    assert r.blocked
    assert r.findings[0].meta["error"] == "json_decode"


def test_schema_accepts_plain_json_without_schema():
    assert Guard([JSONSchemaValidator()]).check('{"ok": true}').passed


def test_schema_enforces_shape():
    schema = {
        "type": "object",
        "properties": {"age": {"type": "integer"}},
        "required": ["age"],
    }
    g = Guard([JSONSchemaValidator(schema)])
    assert g.check('{"age": 30}').passed
    bad = g.check('{"age": "thirty"}')
    assert bad.blocked
    assert bad.findings[0].meta["error"] == "schema_mismatch"
