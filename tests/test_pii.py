from bulwark import Guard, PIIValidator


def test_email_redacted():
    r = Guard([PIIValidator()]).check("ping me at rupesh@example.com please")
    assert r.text == "ping me at [REDACTED_EMAIL] please"
    assert r.redacted and r.passed


def test_valid_credit_card_redacted():
    # 4111 1111 1111 1111 is a Luhn-valid test Visa number.
    r = Guard([PIIValidator()]).check("card 4111 1111 1111 1111")
    assert "[REDACTED_CARD]" in r.text
    assert r.by_validator("pii")[0].meta["kind"] == "credit_card"


def test_invalid_card_number_ignored():
    # Fails Luhn -> should not be flagged as a card.
    r = Guard([PIIValidator()]).check("order 1234 5678 9012 3456 shipped")
    kinds = [f.meta.get("kind") for f in r.by_validator("pii")]
    assert "credit_card" not in kinds


def test_ssn_high_severity():
    r = Guard([PIIValidator()]).check("ssn 123-45-6789")
    f = r.by_validator("pii")[0]
    assert f.meta["kind"] == "ssn"
    assert f.severity.value == "high"


def test_multiple_pii_all_redacted():
    r = Guard([PIIValidator()]).check("a@b.com / 123-45-6789")
    assert "@b.com" not in r.text
    assert "123-45-6789" not in r.text
    assert len(r.findings) == 2


def test_block_mode_blocks():
    r = Guard([PIIValidator(redact=False)]).check("a@b.com")
    assert r.blocked and not r.passed


def test_clean_text_passes_untouched():
    r = Guard([PIIValidator()]).check("nothing sensitive here")
    assert r.text == "nothing sensitive here"
    assert not r.redacted and r.passed


# --- phone-format edge cases -------------------------------------------------

def test_intl_phone_with_country_code_redacted():
    # "+1 " country-code prefix is part of the matched span.
    r = Guard([PIIValidator()]).check("call +1 415-555-2671 now")
    assert r.text == "call [REDACTED_PHONE] now"
    assert r.by_validator("pii")[0].meta["kind"] == "phone"


def test_intl_phone_two_digit_country_code():
    # Country code may be two digits (regex allows \d{1,2}).
    r = Guard([PIIValidator()]).check("ring +44 415-555-2671")
    assert "+44 415-555-2671" not in r.text
    assert "[REDACTED_PHONE]" in r.text


def test_phone_dotted_separators_redacted():
    r = Guard([PIIValidator()]).check("fax 415.555.2671 today")
    assert r.text == "fax [REDACTED_PHONE] today"


def test_phone_parenthesized_area_code_redacted():
    # The parentheses around the area code are included in the redacted span.
    r = Guard([PIIValidator()]).check("dial (415) 555-2671 please")
    assert r.text == "dial [REDACTED_PHONE] please"


def test_phone_extension_base_redacted_but_extension_text_kept():
    # The regex matches only the base number; the trailing extension stays.
    r = Guard([PIIValidator()]).check("Call 415-555-2671 ext. 89")
    assert r.text == "Call [REDACTED_PHONE] ext. 89"
    kinds = [f.meta.get("kind") for f in r.by_validator("pii")]
    assert kinds == ["phone"]


# --- adjacent PII, card separators, SSN boundaries, IP severity ------------

def test_two_adjacent_pii_items_both_redacted_surroundings_kept():
    # Email and phone sit right next to each other; both go, prose survives.
    r = Guard([PIIValidator()]).check("reach a@b.com 415-555-2671 today")
    assert r.text == "reach [REDACTED_EMAIL] [REDACTED_PHONE] today"
    assert "a@b.com" not in r.text and "415-555-2671" not in r.text
    assert len(r.findings) == 2


def test_space_separated_credit_card_redacted():
    r = Guard([PIIValidator()]).check("pay with 4111 1111 1111 1111 now")
    assert "[REDACTED_CARD]" in r.text
    assert "4111 1111 1111 1111" not in r.text
    assert r.by_validator("pii")[0].meta["kind"] == "credit_card"


def test_hyphen_separated_credit_card_redacted():
    r = Guard([PIIValidator()]).check("pay with 4111-1111-1111-1111 now")
    assert "[REDACTED_CARD]" in r.text
    assert "4111-1111-1111-1111" not in r.text
    assert r.by_validator("pii")[0].meta["kind"] == "credit_card"


def test_ssn_embedded_in_longer_digit_run_not_matched():
    # Extra digits on either side break the (?<!\d)...(?!\d) boundaries.
    for text in ("id 123-45-67890 end", "id 0123-45-6789 end"):
        r = Guard([PIIValidator()]).check(text)
        kinds = [f.meta.get("kind") for f in r.by_validator("pii")]
        assert "ssn" not in kinds, text


def test_ipv4_finding_is_low_severity():
    r = Guard([PIIValidator()]).check("server at 192.168.1.1 responded")
    f = r.by_validator("pii")[0]
    assert f.meta["kind"] == "ip_address"
    assert f.severity.value == "low"


def test_isbn_not_flagged_as_phone_or_card():
    # ISBN-13 "978-3-16-148410-0": wrong shape for a phone, and its digit run
    # fails the Luhn check, so it must not be flagged as PII at all.
    r = Guard([PIIValidator()]).check("see ISBN 978-3-16-148410-0 for details")
    assert r.findings == []
    assert not r.redacted and r.passed
