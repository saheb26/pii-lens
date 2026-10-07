"""Command-line interface for pii-lens."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, Literal, Optional, TextIO

import typer

from pii_lens import __version__
from pii_lens.detector import PresidioUnavailableError, detect
from pii_lens.render import render_report

app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,
    subcommand_metavar="",
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


def _configure_output() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            return


def load_text(file: Optional[Path], stream: Optional[TextIO] = None) -> str:
    """Read a UTF-8 file, or stdin when the caller is piping text in."""

    if file is not None:
        return file.read_text(encoding="utf-8-sig", errors="replace")
    source = sys.stdin if stream is None else stream
    if source.isatty():
        typer.echo(
            "Nothing to scan. Pass --file or pipe text on stdin.",
            err=True,
        )
        raise typer.Exit(code=1)
    return source.read()


@app.callback(invoke_without_command=True)
def main(
    file: Annotated[
        Optional[Path],
        typer.Option(
            "--file",
            "-f",
            help="Text file to scan. Reads stdin when omitted.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            show_default=False,
        ),
    ] = None,
    engine: Annotated[
        Literal["auto", "regex", "presidio"],
        typer.Option(
            "--engine",
            help=(
                "Detection engine. auto runs built-in patterns and adds "
                "presidio-analyzer hits when that package is installed."
            ),
        ),
    ] = "auto",
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = None,
) -> None:
    """Highlight PII in a file or on stdin.

    \b
    Examples:
      pii-lens --file logs.txt
      cat logs.txt | pii-lens
    """

    _ = version
    _configure_output()
    text = load_text(file)
    try:
        findings = detect(text, engine=engine)
    except PresidioUnavailableError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    render_report(text, findings)


if __name__ == "__main__":
    app()
