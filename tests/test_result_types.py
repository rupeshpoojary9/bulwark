"""Unit tests for the core result types: `Finding` defaults and the
`Action` / `Severity` string enums.

These pin down the low-level contract that every validator relies on:
a `Finding` built with only its required fields gets sensible defaults,
and the enums behave as plain strings so findings serialize cleanly.
"""
from bulwark import Action, Finding, Severity


def test_finding_defaults():
    # Only the required fields are supplied; the rest come from defaults.
    f = Finding(validator="pii", action=Action.REDACT, message="found an email")
    assert f.validator == "pii"
    assert f.action is Action.REDACT
    assert f.message == "found an email"
    assert f.severity is Severity.MEDIUM
    assert f.span is None
    assert f.replacement is None
    assert f.meta == {}


def test_finding_meta_is_a_fresh_dict_per_instance():
    # `meta` uses default_factory=dict, so instances must not share one dict.
    a = Finding(validator="v", action=Action.ALLOW, message="m")
    b = Finding(validator="v", action=Action.ALLOW, message="m")
    a.meta["kind"] = "email"
    assert b.meta == {}
    assert a.meta is not b.meta


def test_finding_accepts_explicit_overrides():
    f = Finding(
        validator="cards",
        action=Action.BLOCK,
        message="card number",
        severity=Severity.HIGH,
        span=(3, 19),
        replacement="[REDACTED_CARD]",
        meta={"kind": "credit_card"},
    )
    assert f.severity is Severity.HIGH
    assert f.span == (3, 19)
    assert f.replacement == "[REDACTED_CARD]"
    assert f.meta == {"kind": "credit_card"}


def test_action_string_enum_equality():
    # Action is a str-Enum: members equal their string value.
    assert Action.ALLOW == "allow"
    assert Action.REDACT == "redact"
    assert Action.BLOCK == "block"
    assert Action.ALLOW.value == "allow"
    assert isinstance(Action.BLOCK, str)


def test_severity_string_enum_equality():
    assert Severity.LOW == "low"
    assert Severity.MEDIUM == "medium"
    assert Severity.HIGH == "high"
    assert Severity.MEDIUM.value == "medium"
    assert isinstance(Severity.HIGH, str)


def test_enum_members_are_distinct_and_lookupable():
    assert Action.ALLOW != Action.BLOCK
    assert Action("redact") is Action.REDACT
    assert Severity("high") is Severity.HIGH
    # A plain string is only equal to the member sharing its value.
    assert Action.BLOCK != "allow"
