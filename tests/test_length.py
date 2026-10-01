import pytest

from bulwark import Guard, LengthValidator


def test_too_short_blocks():
    r = Guard([LengthValidator(min_chars=20)]).check("too short")
    assert r.blocked
    f = r.by_validator("length")[0]
    assert f.meta["bound"] == "min_chars"


def test_too_long_blocks():
    r = Guard([LengthValidator(max_chars=10)]).check("this is way too long for the bound")
    assert r.blocked
    assert r.by_validator("length")[0].meta["bound"] == "max_chars"


def test_within_bounds_passes():
    r = Guard([LengthValidator(min_chars=5, max_chars=50)]).check("just right")
    assert r.passed
    assert r.by_validator("length") == []


def test_min_words_bound():
    r = Guard([LengthValidator(min_words=5)]).check("too few words")
    assert r.blocked
    f = r.by_validator("length")[0]
    assert f.meta["bound"] == "min_words"
    assert f.meta["n_words"] == 3


def test_max_words_bound():
    r = Guard([LengthValidator(max_words=3)]).check("one two three four five")
    assert r.blocked
    assert r.by_validator("length")[0].meta["bound"] == "max_words"


def test_char_and_word_bounds_independent():
    # Long in words but short in chars should not trigger a char bound that
    # wasn't configured.
    r = Guard([LengthValidator(min_words=2)]).check("a b")
    assert r.passed


def test_no_bounds_raises():
    with pytest.raises(ValueError):
        LengthValidator()


def test_default_action_is_block_not_redact():
    r = Guard([LengthValidator(max_chars=3)]).check("too long")
    f = r.by_validator("length")[0]
    assert f.action.value == "block"
    assert f.span is None  # length findings don't redact a span
