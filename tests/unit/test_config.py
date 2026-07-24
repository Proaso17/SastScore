"""Tests de la configuración .sastcore.yml y el comando init."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sastcore.cli import app
from sastcore.config import (
    CONFIG_FILENAME,
    Config,
    ConfigError,
    OutputFormat,
    default_config_yaml,
    find_config,
    load_config,
)
from sastcore.exit_codes import ExitCode
from sastcore.findings.model import Confidence, Severity


def test_default_config_is_empty() -> None:
    config = Config()
    assert config.exclude == []
    assert config.fail_on is None
    assert config.format is None
    assert config.disabled_rules == []


def test_load_config(tmp_path: Path) -> None:
    path = tmp_path / CONFIG_FILENAME
    path.write_text(
        "exclude: ['vendor/']\n"
        "fail_on: HIGH\n"
        "format: sarif\n"
        "min_confidence: MEDIUM\n"
        "disabled_rules: [py.dangerous.exec]\n",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.exclude == ["vendor/"]
    assert config.fail_on is Severity.HIGH
    assert config.format is OutputFormat.sarif
    assert config.min_confidence is Confidence.MEDIUM
    assert config.disabled_rules == ["py.dangerous.exec"]


def test_load_config_rejects_unknown_field(tmp_path: Path) -> None:
    path = tmp_path / CONFIG_FILENAME
    path.write_text("unknown_option: 1\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_find_config(tmp_path: Path) -> None:
    assert find_config(tmp_path) is None
    (tmp_path / CONFIG_FILENAME).write_text("exclude: []\n", encoding="utf-8")
    assert find_config(tmp_path) is not None


def test_default_template_is_loadable(tmp_path: Path) -> None:
    path = tmp_path / CONFIG_FILENAME
    path.write_text(default_config_yaml(), encoding="utf-8")
    assert load_config(path).exclude == []


def test_init_creates_config(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["init"]).exit_code == ExitCode.OK
    assert (tmp_path / CONFIG_FILENAME).is_file()
    # sin --force sobre un fichero existente -> error
    assert runner.invoke(app, ["init"]).exit_code == ExitCode.ERROR
    # con --force -> ok
    assert runner.invoke(app, ["init", "--force"]).exit_code == ExitCode.OK


def test_config_disabled_rules_filters(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    (tmp_path / CONFIG_FILENAME).write_text(
        "disabled_rules: [py.dangerous.os-system]\n", encoding="utf-8"
    )
    result = runner.invoke(app, ["scan", "app.py", "-f", "json", "--no-cache"])
    ids = [f["rule_id"] for f in json.loads(result.output)["findings"]]
    assert "py.dangerous.os-system" not in ids


def test_config_min_confidence_filters(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text("def q(m, s):\n    return m.raw(s)\n", encoding="utf-8")
    (tmp_path / CONFIG_FILENAME).write_text("min_confidence: MEDIUM\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", "app.py", "-f", "json", "--no-cache"])
    ids = [f["rule_id"] for f in json.loads(result.output)["findings"]]
    assert "py.django.raw-sql" not in ids  # es LOW confidence


def test_format_precedence_cli_over_config(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "clean.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / CONFIG_FILENAME).write_text("format: sarif\n", encoding="utf-8")
    # la CLI (--format json) gana al fichero (sarif)
    result = runner.invoke(app, ["scan", "clean.py", "-f", "json", "--no-cache"])
    assert json.loads(result.output)["tool"] == "sastcore"
