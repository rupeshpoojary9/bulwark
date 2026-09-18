"""Unit tests for the ``_apply_redactions`` helper in ``bulwark.guard``.

These exercise the span-collapsing logic directly (without going through a
validator) so we can pin down the exact behavior for adjacent, nested, and
overlapping REDACT spans.
"""
from bulwark.guard import _apply_redactions
from bulwark.result import Action, Finding


def _redact(start, end, replacement):
    return Finding(
        validator="test",
        action=Action.REDACT,
        message="x",
        span=(start, end),
        replacement=replacement,
    )


def test_no_findings_returns_text_unchanged():
    assert _apply_redactions("hello world", []) == "hello world"


def test_single_span_masked_and_surrounding_preserved():
    findings = [_redact(4, 7, "[X]")]
    assert _apply_redactions("pre foo post", findings) == "pre [X] post"


def test_adjacent_spans_both_applied():
    # "foo" then "bar" with no gap between them: both masked, in order.
    findings = [_redact(0, 3, "[A]"), _redact(3, 6, "[B]")]
    assert _apply_redactions("foobar", findings) == "[A][B]"


def test_adjacent_spans_preserve_surrounding_text():
    # text = "x" + "foo" + "bar" + "y"; the two abutting spans sit in the middle.
    findings = [_redact(1, 4, "[A]"), _redact(4, 7, "[B]")]
    assert _apply_redactions("xfoobary", findings) == "x[A][B]y"


def test_adjacent_spans_applied_regardless_of_finding_order():
    # Same result even when the later span is listed first.
    findings = [_redact(3, 6, "[B]"), _redact(0, 3, "[A]")]
    assert _apply_redactions("foobar", findings) == "[A][B]"


def test_nested_span_widest_wins():
    # Inner span (2,4) is fully contained in outer (0,6): outer wins, inner dropped.
    findings = [_redact(0, 6, "[OUT]"), _redact(2, 4, "[IN]")]
    assert _apply_redactions("foobar", findings) == "[OUT]"


def test_nested_span_widest_wins_regardless_of_order():
    findings = [_redact(2, 4, "[IN]"), _redact(0, 6, "[OUT]")]
    assert _apply_redactions("foobar", findings) == "[OUT]"


def test_same_start_widest_wins():
    # Two spans share a start; the longer one is kept.
    findings = [_redact(0, 3, "[SHORT]"), _redact(0, 6, "[LONG]")]
    assert _apply_redactions("foobar", findings) == "[LONG]"


def test_partial_overlap_leftmost_kept():
    # Overlapping spans are collapsed: the leftmost is kept, the trailing
    # portion of the second span is left untouched.
    findings = [_redact(0, 4, "[A]"), _redact(2, 6, "[B]")]
    assert _apply_redactions("0123456789", findings) == "[A]456789"


def test_non_redact_and_spanless_findings_are_ignored():
    findings = [
        Finding(validator="t", action=Action.ALLOW, message="i", span=(0, 3)),
        Finding(validator="t", action=Action.BLOCK, message="b", span=(3, 6)),
        Finding(validator="t", action=Action.REDACT, message="no span", span=None),
    ]
    assert _apply_redactions("foobar", findings) == "foobar"


def test_replacement_defaults_when_missing():
    findings = [
        Finding(validator="t", action=Action.REDACT, message="m", span=(0, 3))
    ]
    assert _apply_redactions("foobar", findings) == "[REDACTED]bar"
