import pytest

from bulwark import Guard, TopicValidator


def test_deny_mode_blocks_on_match():
    v = TopicValidator(deny={"medical_advice": ["see a doctor", "take ibuprofen"]})
    r = Guard([v]).check("You should see a doctor about that.")
    assert r.blocked
    f = r.by_validator("topic")[0]
    assert f.meta["topic"] == "medical_advice"
    assert f.meta["term"] == "see a doctor"


def test_deny_mode_passes_when_no_term_matches():
    v = TopicValidator(deny={"medical_advice": ["see a doctor"]})
    r = Guard([v]).check("The weather is nice today.")
    assert r.passed


def test_deny_mode_whole_word_boundary():
    # "law" should not fire inside "lawn" or "flaw".
    v = TopicValidator(deny={"legal_advice": ["law"]})
    r = Guard([v]).check("Mow the lawn, it has a flaw.")
    assert r.passed


def test_deny_mode_one_finding_per_topic():
    v = TopicValidator(deny={"medical_advice": ["see a doctor", "take ibuprofen"]})
    r = Guard([v]).check("See a doctor and take ibuprofen.")
    assert len(r.by_validator("topic")) == 1


def test_allow_mode_passes_when_topic_matches():
    v = TopicValidator(allow={"weather": ["forecast", "temperature"]})
    r = Guard([v]).check("The forecast says rain.")
    assert r.passed


def test_allow_mode_blocks_when_no_topic_matches():
    v = TopicValidator(allow={"weather": ["forecast", "temperature"]})
    r = Guard([v]).check("Let's talk about politics instead.")
    assert r.blocked
    f = r.by_validator("topic")[0]
    assert f.meta["topics"] == ["weather"]


def test_requires_exactly_one_of_deny_or_allow():
    with pytest.raises(ValueError):
        TopicValidator()
    with pytest.raises(ValueError):
        TopicValidator(deny={"a": ["x"]}, allow={"b": ["y"]})


def test_case_insensitive():
    v = TopicValidator(deny={"medical_advice": ["see a doctor"]})
    r = Guard([v]).check("SEE A DOCTOR immediately.")
    assert r.blocked
