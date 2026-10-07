"""Find high-risk personal data in plain text.

The built-in scanner is a pattern matcher with checksums, so the CLI works
without a spaCy model. When presidio-analyzer is installed, ``auto`` mode
merges its recognizer hits with those patterns.
"""

from __future__ import annotations

import inspect
import re
from dataclasses import dataclass
from typing import Any, Iterable

ENTITY_TYPES = (
    "CREDIT_CARD",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "SSN",
    "US_BANK_NUMBER",
)

_PRIORITY = {
    "CREDIT_CARD": 50,
    "SSN": 40,
    "US_BANK_NUMBER": 30,
    "PHONE_NUMBER": 20,
    "EMAIL_ADDRESS": 10,
}

_ENTITY_ALIASES = {
    "CREDIT_CARD": "CREDIT_CARD",
    "EMAIL_ADDRESS": "EMAIL_ADDRESS",
    "PHONE_NUMBER": "PHONE_NUMBER",
    "US_SSN": "SSN",
    "SSN": "SSN",
    "US_BANK_NUMBER": "US_BANK_NUMBER",
    "ABA_ROUTING_NUMBER": "US_BANK_NUMBER",
}

_PRESIDIO_SCORE_THRESHOLD = 0.4
_LABEL_LOOKAHEAD = 16
_PREVIOUS_LINE_LIMIT = 80

_ENGINES = {"auto", "regex", "presidio"}


class PresidioUnavailableError(RuntimeError):
    """Raised when the Presidio engine is requested but cannot be loaded."""

    def __init__(self) -> None:
        super().__init__(
            "presidio-analyzer is not available. "
            'Install it with: pip install "pii-lens[presidio]"'
        )


@dataclass(frozen=True)
class Finding:
    """A single PII span. Offsets are Python indexes into the scanned text."""

    entity: str
    start: int
    end: int


def summarize(findings: Iterable[Finding]) -> dict[str, int]:
    """Count findings for every supported entity, including zeros."""

    counts = {entity: 0 for entity in ENTITY_TYPES}
    for finding in findings:
        if finding.entity in counts:
            counts[finding.entity] += 1
    return counts


def resolve_overlaps(findings: Iterable[Finding]) -> list[Finding]:
    """Keep one span per overlap, preferring higher-priority entities."""

    unique: list[Finding] = []
    seen: set[tuple[str, int, int]] = set()
    for finding in findings:
        if finding.entity not in _PRIORITY or finding.end <= finding.start:
            continue
        key = (finding.entity, finding.start, finding.end)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)

    ranked = sorted(
        unique,
        key=lambda finding: (
            -_PRIORITY[finding.entity],
            -(finding.end - finding.start),
            finding.start,
        ),
    )
    accepted: list[Finding] = []
    for finding in ranked:
        overlaps = any(
            finding.start < other.end and other.start < finding.end
            for other in accepted
        )
        if overlaps:
            continue
        accepted.append(finding)
    accepted.sort(key=lambda finding: finding.start)
    return accepted


def detect(text: str, engine: str = "auto") -> list[Finding]:
    """Return non-overlapping PII spans in ``text``.

    ``regex`` uses the built-in patterns. ``presidio`` uses Microsoft's
    recognizers and raises ``PresidioUnavailableError`` when they are not
    installed. ``auto`` runs the built-in patterns and adds Presidio hits
    when the package imports.
    """

    normalized = engine.strip().lower()
    if normalized not in _ENGINES:
        raise ValueError(
            f"Unknown engine '{engine}'. Expected auto, regex, or presidio."
        )
    if normalized == "regex":
        return _detect_regex(text)

    presidio_findings = _detect_presidio(text)
    if normalized == "presidio":
        if presidio_findings is None:
            raise PresidioUnavailableError()
        return presidio_findings

    regex_findings = _detect_regex(text)
    if presidio_findings is None:
        return regex_findings
    return resolve_overlaps([*regex_findings, *presidio_findings])


def _digits(value: str) -> str:
    return "".join(character for character in value if character.isdigit())


def _passes_luhn(number: str) -> bool:
    total = 0
    for index, character in enumerate(reversed(number)):
        digit = int(character)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _matches_card_brand(number: str) -> bool:
    length = len(number)
    if number.startswith("4") and length in {13, 16, 19}:
        return True
    if length == 15 and number[:2] in {"34", "37"}:
        return True
    if length == 16 and 51 <= int(number[:2]) <= 55:
        return True
    if length == 16 and number.startswith("2") and 2221 <= int(number[:4]) <= 2720:
        return True
    if length == 16 and (
        number.startswith("6011")
        or number.startswith("65")
        or 644 <= int(number[:3]) <= 649
    ):
        return True
    return False


def _is_card_number(number: str) -> bool:
    if not number.isdigit() or not 13 <= len(number) <= 19:
        return False
    if not _matches_card_brand(number):
        return False
    return _passes_luhn(number)


def _passes_aba(number: str) -> bool:
    """ABA routing checksum: 3(d1+d4+d7)+7(d2+d5+d8)+(d3+d6+d9) ≡ 0 (mod 10)."""

    if len(number) != 9 or not number.isdigit():
        return False
    weights = (3, 7, 1, 3, 7, 1, 3, 7, 1)
    checksum = sum(weight * int(digit) for weight, digit in zip(weights, number))
    return checksum != 0 and checksum % 10 == 0


def _is_valid_ssn(area: str, group: str, serial: str) -> bool:
    if area in {"000", "666"} or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    return True


def _is_nanp(digits: str) -> bool:
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) != 10:
        return False
    return digits[0] in "23456789" and digits[3] in "23456789"


def _has_label(pattern: Any, text: str, start: int, end: int) -> bool:
    """True when a label sits on this line, or the line is only the value."""

    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    before = text[line_start:start]
    after = text[end : min(line_end, end + _LABEL_LOOKAHEAD)]
    if pattern.search(before) or pattern.search(after):
        return True
    if before.strip():
        return False
    if line_start == 0:
        return False
    previous_end = line_start - 1
    previous_start = text.rfind("\n", 0, previous_end) + 1
    previous_line = text[previous_start:previous_end]
    if len(previous_line) > _PREVIOUS_LINE_LIMIT:
        previous_line = previous_line[-_PREVIOUS_LINE_LIMIT:]
    return pattern.search(previous_line) is not None


_CARD = re.compile(r"(?<!\d)(?:\d[ \t-]?){12,18}\d(?!\d)", re.ASCII)
_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}\b",
    re.ASCII,
)
_PHONE = re.compile(
    r"(?<!\d)"
    r"(?:\+?1[-. \t]?)?"
    r"(?:\(\d{3}\)[-. \t]?|\d{3}[-. \t])"
    r"\d{3}[-. \t]\d{4}"
    r"(?!\d)",
    re.ASCII,
)
_SSN = re.compile(r"(?<!\d)(\d{3})([- ])(\d{2})\2(\d{4})(?!\d)", re.ASCII)
_ACCOUNT = re.compile(r"(?<!\d)(\d{8,17})(?!\d)", re.ASCII)
_ROUTING = re.compile(r"(?<!\d)(\d{9})(?!\d)", re.ASCII)
_ACCOUNT_CONTEXT = re.compile(
    r"\b(?:bank[ \t]+account|account(?:[ \t]+number)?|acct|checking|savings)\b",
    re.IGNORECASE | re.ASCII,
)
_ROUTING_CONTEXT = re.compile(
    r"\b(?:routing(?:[ \t]+number)?|aba(?:[ \t]+number)?|rtn|bank[ \t]+routing)\b",
    re.IGNORECASE | re.ASCII,
)


def _detect_regex(text: str) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_card_findings(text))
    findings.extend(_email_findings(text))
    findings.extend(_phone_findings(text))
    findings.extend(_ssn_findings(text))
    findings.extend(_bank_findings(text))
    return resolve_overlaps(findings)


def _card_findings(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _CARD.finditer(text):
        if _is_card_number(_digits(match.group())):
            findings.append(Finding("CREDIT_CARD", match.start(), match.end()))
    return findings


def _email_findings(text: str) -> list[Finding]:
    return [
        Finding("EMAIL_ADDRESS", match.start(), match.end())
        for match in _EMAIL.finditer(text)
    ]


def _phone_findings(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _PHONE.finditer(text):
        if _is_nanp(_digits(match.group())):
            findings.append(Finding("PHONE_NUMBER", match.start(), match.end()))
    return findings


def _ssn_findings(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _SSN.finditer(text):
        area, _separator, group, serial = match.groups()
        if _is_valid_ssn(area, group, serial):
            findings.append(Finding("SSN", match.start(), match.end()))
    return findings


def _bank_findings(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _ACCOUNT.finditer(text):
        if _has_label(_ACCOUNT_CONTEXT, text, match.start(), match.end()):
            findings.append(Finding("US_BANK_NUMBER", match.start(), match.end()))
    for match in _ROUTING.finditer(text):
        number = match.group(1)
        if not _passes_aba(number):
            continue
        if _has_label(_ROUTING_CONTEXT, text, match.start(), match.end()):
            findings.append(Finding("US_BANK_NUMBER", match.start(), match.end()))
    return findings


_presidio_cache: Any = object()
_PRESIDIO_UNSET = _presidio_cache


def _load_presidio_recognizers() -> tuple[Any, ...] | None:
    """Build Presidio pattern recognizers without loading a spaCy model."""

    global _presidio_cache
    if _presidio_cache is not _PRESIDIO_UNSET:
        return _presidio_cache
    try:
        _presidio_cache = _build_presidio_recognizers()
    except Exception:
        _presidio_cache = None
    return _presidio_cache


def _build_presidio_recognizers() -> tuple[Any, ...] | None:
    try:
        from presidio_analyzer.predefined_recognizers import (
            CreditCardRecognizer,
            EmailRecognizer,
            PhoneRecognizer,
            UsBankRecognizer,
            UsSsnRecognizer,
        )
    except ImportError:
        return None

    phone_parameters = inspect.signature(PhoneRecognizer).parameters
    if "supported_regions" in phone_parameters:
        phone = PhoneRecognizer(supported_regions=["US"])
    else:
        phone = PhoneRecognizer()

    recognizers: list[tuple[str, Any]] = [
        ("CREDIT_CARD", CreditCardRecognizer()),
        ("EMAIL_ADDRESS", EmailRecognizer()),
        ("PHONE_NUMBER", phone),
        ("SSN", UsSsnRecognizer()),
        ("US_BANK_NUMBER", UsBankRecognizer()),
    ]
    try:
        from presidio_analyzer.predefined_recognizers import AbaRoutingRecognizer
    except ImportError:
        pass
    else:
        recognizers.append(("US_BANK_NUMBER", AbaRoutingRecognizer()))
    return tuple(recognizers)


def _analyze(recognizer: Any, text: str, entities: list[str]) -> list[Any]:
    try:
        results = recognizer.analyze(text=text, entities=entities)
    except TypeError:
        results = recognizer.analyze(text, entities)
    return list(results)


def _detect_presidio(text: str) -> list[Finding] | None:
    recognizers = _load_presidio_recognizers()
    if recognizers is None:
        return None

    findings: list[Finding] = []
    for label, recognizer in recognizers:
        entities = list(getattr(recognizer, "supported_entities", []) or [])
        if not entities:
            continue
        try:
            results = _analyze(recognizer, text, entities)
        except Exception:
            continue
        for result in results:
            score = getattr(result, "score", 1.0)
            if score < _PRESIDIO_SCORE_THRESHOLD:
                continue
            mapped = _ENTITY_ALIASES.get(getattr(result, "entity_type", ""), label)
            if mapped not in _PRIORITY:
                continue
            start = int(result.start)
            end = int(result.end)
            if start < 0 or end > len(text) or start >= end:
                continue
            findings.append(Finding(mapped, start, end))
    return resolve_overlaps(findings)
