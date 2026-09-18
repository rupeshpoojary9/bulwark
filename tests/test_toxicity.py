import pytest

from bulwark import Guard, Severity, ToxicityValidator


@pytest.mark.parametrize("text", [
    "you are an idiot",
    "shut up already",
    "I will hurt you",
    "kill yourself",
    "that is pathetic and worthless",
])
def test_toxic_blocked(text):
    assert Guard([ToxicityValidator()]).check(text).blocked


@pytest.mark.parametrize("text", [
    "the assistant was helpful",   # contains 'ass' but not a lexicon word
    "our class starts at nine",
    "please water the grass",
    "great work on the report",
    "could you clarify the requirement",
])
def test_benign_passes(text):
    assert Guard([ToxicityValidator()]).check(text).passed


def test_whole_word_matching_no_substring_false_positive():
    # 'assistant'/'class'/'grass' must not trigger any finding
    r = Guard([ToxicityValidator()]).check("the assistant led the class on the grass")
    assert r.findings == []


def test_category_and_term_recorded():
    r = Guard([ToxicityValidator()]).check("you moron")
    f = r.findings[0]
    assert f.meta["category"] == "insult"
    assert f.meta["term"] == "moron"


def test_threats_are_high_severity():
    r = Guard([ToxicityValidator()]).check("I will hurt you")
    assert r.findings[0].severity is Severity.HIGH


def test_redact_mode_masks_term():
    r = Guard([ToxicityValidator(block=False)]).check("you idiot")
    assert r.passed
    assert "[REDACTED_TOXIC]" in r.text
    assert "idiot" not in r.text


def test_case_insensitive():
    assert Guard([ToxicityValidator()]).check("You IDIOT").blocked


def test_extra_terms_extend_lexicon():
    v = ToxicityValidator(extra_terms={"nonsense": ("insult", Severity.LOW)})
    assert Guard([v]).check("what nonsense").blocked
    # base lexicon still active
    assert Guard([v]).check("you idiot").blocked


def test_multiple_toxic_terms_all_reported():
    r = Guard([ToxicityValidator()]).check("you stupid worthless loser")
    terms = sorted(f.meta["term"] for f in r.findings)
    assert terms == ["loser", "stupid", "worthless"]
