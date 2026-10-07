"""CLI file, stdin, and usage paths."""

import importlib.util
import io
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from pii_lens import __version__
from pii_lens.cli import app, load_text

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "examples" / "sample.txt"
runner = CliRunner()


def test_file_scan_prints_highlights_metric_and_panel() -> None:
    result = runner.invoke(app, ["--engine", "regex", "--file", str(SAMPLE_PATH)])
    assert result.exit_code == 0, result.output
    output = result.output
    assert "ada@example.com" in output
    assert "(415) 555-0134" in output
    assert "123-45-6789" in output
    assert "4111-1111-1111-1111" in output
    assert "9876543210" in output
    assert "123456780" in output
    assert "[6] High-Risk Secrets Detected in Payload" in output
    assert "CREDIT_CARD: 1" in output
    assert "EMAIL_ADDRESS: 1" in output
    assert "PHONE_NUMBER: 1" in output
    assert "SSN: 1" in output
    assert "US_BANK_NUMBER: 2" in output
    assert "Don't send this to an open API" in output
    assert "https://counselnode.com" in output
    assert "CounselNode's VPC Sidecar" in output


def test_stdin_scan() -> None:
    payload = SAMPLE_PATH.read_text(encoding="utf-8")
    result = runner.invoke(app, ["--engine", "regex"], input=payload)
    assert result.exit_code == 0, result.output
    assert "[6] High-Risk Secrets Detected in Payload" in result.output
    assert "ada@example.com" in result.output


def test_empty_stdin_reports_zero() -> None:
    result = runner.invoke(app, ["--engine", "regex"], input="")
    assert result.exit_code == 0, result.output
    assert "[0] High-Risk Secrets Detected in Payload" in result.output
    assert "https://counselnode.com" in result.output


def test_interactive_terminal_without_input_exits() -> None:
    class _Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    with pytest.raises(typer.Exit) as caught:
        load_text(None, _Tty())
    assert caught.value.exit_code == 1


def test_temp_file_option(tmp_path: Path) -> None:
    payload = tmp_path / "notes.txt"
    payload.write_text("reach ada@example.com\n", encoding="utf-8")
    result = runner.invoke(app, ["--engine", "regex", "--file", str(payload)])
    assert result.exit_code == 0, result.output
    assert "[1] High-Risk Secrets Detected in Payload" in result.output
    assert "EMAIL_ADDRESS: 1" in result.output


def test_missing_file_is_rejected(tmp_path: Path) -> None:
    result = runner.invoke(app, ["--file", str(tmp_path / "missing.txt")])
    assert result.exit_code != 0


def test_directory_is_rejected(tmp_path: Path) -> None:
    result = runner.invoke(app, ["--file", str(tmp_path)])
    assert result.exit_code != 0


def test_help_lists_file_and_stdin() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "--file" in result.output
    assert "stdin" in result.output


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_unknown_engine_is_rejected() -> None:
    result = runner.invoke(app, ["--engine", "nope"], input="ada@example.com")
    assert result.exit_code != 0


def test_presidio_engine_without_package() -> None:
    if importlib.util.find_spec("presidio_analyzer") is not None:
        pytest.skip("presidio-analyzer is installed")
    result = runner.invoke(app, ["--engine", "presidio"], input="ada@example.com")
    assert result.exit_code == 2
    assert "presidio" in result.output.lower()
