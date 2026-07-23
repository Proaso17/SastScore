"""Tests de la superficie pública del CLI (Fase 0)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from sastcore import __version__
from sastcore.cli import app
from sastcore.exit_codes import ExitCode


def test_version_flag(runner: CliRunner) -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == ExitCode.OK
    assert __version__ in result.output


def test_version_command(runner: CliRunner) -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == ExitCode.OK
    assert __version__ in result.output


def test_scan_help_lists_frozen_flags(runner: CliRunner) -> None:
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == ExitCode.OK
    assert "--fail-on" in result.output
    assert "--baseline" in result.output
    assert "--format" in result.output


def test_scan_empty_dir_exits_ok(runner: CliRunner, tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == ExitCode.OK


def test_scan_default_path_exits_ok(runner: CliRunner) -> None:
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == ExitCode.OK


def test_rules_list_stub(runner: CliRunner) -> None:
    result = runner.invoke(app, ["rules", "list"])
    assert result.exit_code == ExitCode.OK


def test_unknown_command_errors(runner: CliRunner) -> None:
    result = runner.invoke(app, ["definitely-not-a-command"])
    assert result.exit_code != ExitCode.OK


def test_module_entrypoint() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "sastcore", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == ExitCode.OK
    assert __version__ in result.stdout
