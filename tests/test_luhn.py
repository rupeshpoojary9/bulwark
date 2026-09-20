import pytest

from bulwark.validators.pii import _luhn_ok

# Well-known Luhn-valid numbers: brand test cards + the canonical
# Wikipedia example (79927398713).
VALID = [
    "4111111111111111",   # Visa test number
    "5500005555555559",   # Mastercard test number
    "340000000000009",    # Amex test number (15 digits)
    "6011000000000004",   # Discover test number
    "79927398713",        # canonical Luhn example
]

# The three neighbours of the canonical example fail the check, plus a couple
# of obviously-not-a-card digit runs.
INVALID = [
    "79927398710",
    "79927398711",
    "79927398714",
    "4111111111111112",   # last digit off by one
    "1234567890123456",
]


@pytest.mark.parametrize("digits", VALID)
def test_luhn_accepts_valid(digits):
    assert _luhn_ok(digits) is True


@pytest.mark.parametrize("digits", INVALID)
def test_luhn_rejects_invalid(digits):
    assert _luhn_ok(digits) is False


def test_luhn_single_zero_is_valid():
    # A lone "0" has checksum 0, which is divisible by 10.
    assert _luhn_ok("0") is True


def test_luhn_empty_string_is_valid():
    # No digits -> total 0 -> passes; the card regex never feeds it an empty
    # string, but the helper should not raise.
    assert _luhn_ok("") is True
