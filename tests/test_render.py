"""Terminal rendering: highlight style, counts, and the closing panel."""

import io

import pytest
from rich.console import Console
from rich.style import Style

from pii_lens.detector import detect
from pii_lens.render import CTA, highlight, render_report


def test_call_to_action_copy() -> None:
    assert CTA == (
        "🛡️ Don't send this to an open API. CounselNode's VPC Sidecar "
        "automatically redacts these tokens before they hit the LLM and "
        "processes them on private infrastructure. Secure your pipeline: "
        "https://counselnode.com"
    )


def test_highlight_uses_bold_white_on_red() -> None:
    text = "mail ada@example.com today"
    findings = detect(text, engine="regex")
    rendered = highlight(text, findings)
    assert len(rendered.spans) == 1
    span = rendered.spans[0]
    assert text[span.start : span.end] == "ada@example.com"
    style = span.style
    if isinstance(style, str):
        style = Style.parse(style)
    assert style.bold
    assert style.color is not None
    assert style.bgcolor is not None
    assert "red" in style.bgcolor.name
    assert "white" in style.color.name


def test_terminal_output_emits_red_background(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    text = "mail ada@example.com today"
    findings = detect(text, engine="regex")
    buffer = io.StringIO()
    console = Console(
        file=buffer,
        force_terminal=True,
        color_system="standard",
        highlight=False,
        legacy_windows=False,
        width=80,
    )
    console.print(highlight(text, findings))
    output = buffer.getvalue()
    assert "ada@example.com" in output
    # bold (1), white foreground (37), red background (41)
    assert "\x1b[1;37;41m" in output


def test_report_contains_metric_breakdown_and_panel() -> None:
    text = "ada@example.com paid with 4111111111111111"
    findings = detect(text, engine="regex")
    buffer = io.StringIO()
    console = Console(file=buffer, highlight=False, force_terminal=False, width=240)
    render_report(text, findings, console)
    flattened = " ".join(buffer.getvalue().split())
    assert "[2] High-Risk Secrets Detected in Payload" in flattened
    assert "CREDIT_CARD: 1" in flattened
    assert "EMAIL_ADDRESS: 1" in flattened
    assert " ".join(CTA.split()) in flattened
    assert "ada@example.com" in flattened
    assert "4111111111111111" in flattened


def test_clean_payload_still_prints_zero_and_panel() -> None:
    buffer = io.StringIO()
    console = Console(file=buffer, highlight=False, force_terminal=False, width=240)
    render_report("order 48291 shipped", [], console)
    flattened = " ".join(buffer.getvalue().split())
    assert "[0] High-Risk Secrets Detected in Payload" in flattened
    assert "https://counselnode.com" in flattened


def test_brackets_in_the_payload_stay_literal() -> None:
    text = "[red]ada@example.com[/red]"
    findings = detect(text, engine="regex")
    buffer = io.StringIO()
    console = Console(file=buffer, highlight=False, force_terminal=False, width=80)
    render_report(text, findings, console)
    output = buffer.getvalue()
    assert "[red]" in output
    assert "ada@example.com" in output
    assert "[1] High-Risk Secrets Detected in Payload" in output
