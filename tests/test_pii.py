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
