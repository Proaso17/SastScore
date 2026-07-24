"""Tests de la superficie pública del CLI (Fase 0)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from sastcore import __version__
from sastcore.cli import app
from sastcore.exit_codes import ExitCode

_DIRTY_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "dirty"


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
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-cache"])
    assert result.exit_code == ExitCode.OK


def test_scan_default_path_exits_ok(runner: CliRunner) -> None:
    result = runner.invoke(app, ["scan", "--no-cache"])
    assert result.exit_code == ExitCode.OK


def test_rules_list_stub(runner: CliRunner) -> None:
    result = runner.invoke(app, ["rules", "list"])
    assert result.exit_code == ExitCode.OK


def test_unknown_command_errors(runner: CliRunner) -> None:
    result = runner.invoke(app, ["definitely-not-a-command"])
    assert result.exit_code != ExitCode.OK


def test_scan_dirty_fixture_fail_on_high_exits_findings(runner: CliRunner) -> None:
    result = runner.invoke(app, ["scan", str(_DIRTY_FIXTURE), "--fail-on", "HIGH", "--no-cache"])
    assert result.exit_code == ExitCode.FINDINGS


def test_scan_json_format(runner: CliRunner) -> None:
    result = runner.invoke(app, ["scan", str(_DIRTY_FIXTURE), "--format", "json", "--no-cache"])
    assert result.exit_code == ExitCode.OK
    data = json.loads(result.output)
    assert data["tool"] == "sastcore"
    assert len(data["findings"]) > 0


def test_scan_missing_path_exits_error(runner: CliRunner) -> None:
    result = runner.invoke(app, ["scan", "does-not-exist-xyz-123"])
    assert result.exit_code == ExitCode.ERROR


def test_scan_sarif_to_file(runner: CliRunner, tmp_path: Path) -> None:
    out = tmp_path / "out.sarif"
    result = runner.invoke(
        app, ["scan", str(_DIRTY_FIXTURE), "--format", "sarif", "-o", str(out), "--no-cache"]
    )
    assert result.exit_code == ExitCode.OK
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "sastcore"


def test_baseline_create_then_scan_reports_no_new(runner: CliRunner, tmp_path: Path) -> None:
    baseline = tmp_path / "bl.json"
    created = runner.invoke(app, ["baseline", "create", str(_DIRTY_FIXTURE), "-o", str(baseline)])
    assert created.exit_code == ExitCode.OK
    assert baseline.is_file()
    # Con el baseline de todos los hallazgos, no hay nuevos → no falla por --fail-on.
    result = runner.invoke(
        app,
        [
            "scan",
            str(_DIRTY_FIXTURE),
            "--baseline",
            str(baseline),
            "--fail-on",
            "HIGH",
            "--no-cache",
        ],
    )
    assert result.exit_code == ExitCode.OK


def test_module_entrypoint() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "sastcore", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == ExitCode.OK
    assert __version__ in result.stdout
