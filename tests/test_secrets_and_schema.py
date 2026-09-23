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


@pytest.mark.parametrize("text,kind", [
    ("slack token xoxb-" + "1" * 12 + " leaked", "slack_token"),
    ("slack token xoxp-" + "a" * 12 + " leaked", "slack_token"),
    ("slack bot xoxb-2345678901-2345678901-abcdefghij here", "slack_token"),
    ("google key AIza" + "B" * 35 + " oops", "google_api_key"),
    ("google key AIzaSy" + "c" * 33 + " oops", "google_api_key"),
])
def test_slack_and_google_secrets_blocked(text, kind):
    r = Guard([SecretsValidator()]).check(text)
    assert r.blocked
    assert r.findings[0].meta["kind"] == kind


@pytest.mark.parametrize("header", [
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
])
def test_private_key_pem_blocked(header):
    pem = f"{header}\nMIIEvQIBADANBgkqh\n-----END PRIVATE KEY-----"
    r = Guard([SecretsValidator()]).check(pem)
    assert r.blocked
    assert r.findings[0].meta["kind"] == "private_key"


def test_slack_and_google_redact_mode():
    text = "cfg xoxb-" + "1" * 12 + " and AIza" + "B" * 35
    r = Guard([SecretsValidator(block=False)]).check(text)
    assert r.passed
    assert "[REDACTED_SLACK_TOKEN]" in r.text
    assert "[REDACTED_GOOGLE_API_KEY]" in r.text


def test_private_key_redact_mode():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
    r = Guard([SecretsValidator(block=False)]).check(pem)
    assert r.passed
    assert "[REDACTED_PRIVATE_KEY]" in r.text
    # only the BEGIN header is matched/masked; the body is left intact
    assert "abc" in r.text


def test_short_slack_prefix_is_not_a_false_positive():
    # too few trailing chars to satisfy the {10,} quantifier
    assert Guard([SecretsValidator()]).check("say xoxb-12 to me").passed


def test_plain_google_word_is_not_a_false_positive():
    # "AIza" alone (no 35-char key body) must not match
    assert Guard([SecretsValidator()]).check("the AIza project update").passed


def test_multiple_secrets_all_reported():
    # Three distinct credential types in one blob -> one finding each, no misses.
    text = (
        "aws AKIAIOSFODNN7EXAMPLE "
        "gh ghp_" + "a" * 36 + " "
        "openai sk-" + "b" * 32
    )
    r = Guard([SecretsValidator()]).check(text)
    assert r.blocked
    kinds = sorted(f.meta["kind"] for f in r.findings)
    assert kinds == ["aws_access_key_id", "github_token", "openai_api_key"]


def test_multiple_secrets_same_kind_all_reported():
    # Two AWS keys -> two separate findings with distinct spans.
    text = "first AKIAIOSFODNN7EXAMPLE then AKIA1234567890ABCDEF end"
    r = Guard([SecretsValidator()]).check(text)
    aws = [f for f in r.findings if f.meta["kind"] == "aws_access_key_id"]
    assert len(aws) == 2
    assert aws[0].span != aws[1].span


def test_multiple_secrets_all_redacted():
    text = "AKIAIOSFODNN7EXAMPLE and sk-" + "b" * 32
    r = Guard([SecretsValidator(block=False)]).check(text)
    assert r.passed
    assert "[REDACTED_AWS_ACCESS_KEY_ID]" in r.text
    assert "[REDACTED_OPENAI_API_KEY]" in r.text


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
