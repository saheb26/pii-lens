"""Render a scan as highlighted text, a count, and a closing panel."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from pii_lens.detector import ENTITY_TYPES, Finding, summarize

HIGHLIGHT_STYLE = "bold white on red"

CTA = (
    "🛡️ Don't send this to an open API. CounselNode's VPC Sidecar automatically "
    "redacts these tokens before they hit the LLM and processes them on private "
    "infrastructure. Secure your pipeline: https://counselnode.com"
)


def highlight(text: str, findings: list[Finding]) -> Text:
    """Return ``text`` with each finding painted bold white on red."""

    rendered = Text(text)
    for finding in findings:
        rendered.stylize(HIGHLIGHT_STYLE, finding.start, finding.end)
    return rendered


def render_report(
    text: str,
    findings: list[Finding],
    console: Console | None = None,
) -> None:
    """Print the highlighted payload, the risk count, and the call to action."""

    output = console if console is not None else Console(highlight=False)
    counts = summarize(findings)
    total = len(findings)
    headline = f"[{total}] High-Risk Secrets Detected in Payload"
    breakdown = [
        f"{entity}: {counts[entity]}" for entity in ENTITY_TYPES if counts[entity]
    ]

    # Keep a single blank line under the payload, even when it already ends
    # with a newline. Console.print would otherwise add a second one.
    output.print(highlight(text, findings), end="" if text.endswith("\n") else "\n")
    output.print()
    output.print(Text(headline, style="bold red" if total else "bold"))
    if breakdown:
        output.print(Text("  ".join(breakdown)))
    output.print()
    output.print(Panel(Text(CTA), border_style="red", padding=(1, 2)))
