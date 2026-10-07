"""Pattern coverage for the built-in PII scanner."""

import importlib.util
from pathlib import Path

import pytest

from pii_lens.detector import PresidioUnavailableError, detect, summarize

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "examples" / "sample.txt"


def _spans(text: str, engine: str = "regex") -> list[tuple[str, str]]:
    return [
        (finding.entity, text[finding.start : finding.end])
        for finding in detect(text, engine=engine)
    ]


def test_sample_log_counts_and_slices() -> None:
    text = SAMPLE_PATH.read_text(encoding="utf-8")
    findings = detect(text, engine="regex")
    assert summarize(findings) == {
        "CREDIT_CARD": 1,
        "EMAIL_ADDRESS": 1,
        "PHONE_NUMBER": 1,
        "SSN": 1,
        "US_BANK_NUMBER": 2,
    }
    snippets = {text[finding.start : finding.end] for finding in findings}
    assert snippets == {
        "ada@example.com",
        "(415) 555-0134",
        "123-45-6789",
        "4111-1111-1111-1111",
        "9876543210",
        "123456780",
    }
    assert "48291" not in snippets
    assert "100234" not in snippets


def test_empty_text() -> None:
    assert detect("", engine="regex") == []


def test_unknown_engine() -> None:
    with pytest.raises(ValueError):
        detect("ada@example.com", engine="satellite")


def test_email_ignores_trailing_comma() -> None:
    text = "Email ada@example.com, thanks"
    assert _spans(text) == [("EMAIL_ADDRESS", "ada@example.com")]


def test_offsets_are_characters_not_bytes() -> None:
    text = "café ada@example.com"
    assert _spans(text) == [("EMAIL_ADDRESS", "ada@example.com")]


@pytest.mark.parametrize(
    "number",
    [
        "(415) 555-0134",
        "415-555-0134",
        "415.555.0134",
        "+1 415 555 0134",
        "1-415-555-0134",
        "+1 (415) 555-0134",
        "(415)555-0134",
    ],
)
def test_phone_formats(number: str) -> None:
    text = f"call {number} today"
    assert _spans(text) == [("PHONE_NUMBER", number)]


@pytest.mark.parametrize(
    "number",
    ["4155550134", "015-555-0134", "415-155-0134", "555-0134"],
)
def test_phone_rejected(number: str) -> None:
    assert _spans(f"call {number} today") == []


@pytest.mark.parametrize(
    "number",
    ["123-45-6789", "123 45 6789"],
)
def test_ssn_formats(number: str) -> None:
    assert _spans(f"ssn {number}") == [("SSN", number)]


@pytest.mark.parametrize(
    "number",
    [
        "000-12-3456",
        "666-45-6789",
        "901-45-6789",
        "123-00-6789",
        "123-45-0000",
        "123-45 6789",
    ],
)
def test_ssn_rejected(number: str) -> None:
    assert _spans(f"ssn {number}") == []


@pytest.mark.parametrize(
    "number",
    [
        "4111111111111111",
        "4111-1111-1111-1111",
        "4111 1111 1111 1111",
        "5500000000000004",
        "5555555555554444",
        "378282246310005",
        "3782 822463 10005",
        "6011111111111117",
        "4222222222222",
    ],
)
def test_credit_cards(number: str) -> None:
    assert _spans(f"card {number}") == [("CREDIT_CARD", number)]


def test_invalid_luhn_is_ignored() -> None:
    assert _spans("card 4111111111111112") == []


def test_adjacent_cards_are_both_found() -> None:
    text = "4111111111111111 5500000000000004"
    assert _spans(text) == [
        ("CREDIT_CARD", "4111111111111111"),
        ("CREDIT_CARD", "5500000000000004"),
    ]


def test_valid_card_with_account_label_stays_a_card() -> None:
    text = "account number 4111111111111111"
    assert _spans(text) == [("CREDIT_CARD", "4111111111111111")]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("account number 1234567", []),
        ("account number 12345678", [("US_BANK_NUMBER", "12345678")]),
        (
            "account number 12345678901234567",
            [("US_BANK_NUMBER", "12345678901234567")],
        ),
        ("account number 123456789012345678", []),
        ("acct 9876543210", [("US_BANK_NUMBER", "9876543210")]),
        ("savings 1234567890123456", [("US_BANK_NUMBER", "1234567890123456")]),
    ],
)
def test_account_numbers(text: str, expected: list[tuple[str, str]]) -> None:
    assert _spans(text) == expected


def test_routing_number_on_its_own_line() -> None:
    text = "routing number:\n123456780"
    assert _spans(text) == [("US_BANK_NUMBER", "123456780")]


def test_bad_routing_checksum_is_ignored() -> None:
    assert _spans("routing number 123456789") == []


def test_routing_without_label_is_ignored() -> None:
    assert _spans("id 123456780") == []


def test_following_line_does_not_steal_the_label() -> None:
    text = "account number 9876543210\norder 12345678"
    assert _spans(text) == [("US_BANK_NUMBER", "9876543210")]


def test_auto_finds_email_with_or_without_presidio() -> None:
    findings = detect("ada@example.com", engine="auto")
    assert any(finding.entity == "EMAIL_ADDRESS" for finding in findings)
    if importlib.util.find_spec("presidio_analyzer") is None:
        assert findings == detect("ada@example.com", engine="regex")
        with pytest.raises(PresidioUnavailableError):
            detect("ada@example.com", engine="presidio")
