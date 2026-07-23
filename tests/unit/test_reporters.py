"""Tests de los reporters de consola y JSON."""

from __future__ import annotations

import io
import json

from rich.console import Console

from sastcore.findings.model import Confidence, Engine, Finding, Location, Severity
from sastcore.reporters.console import ConsoleReporter
from sastcore.reporters.json_ import JSONReporter


def _finding() -> Finding:
    return Finding(
        rule_id="secrets.aws.access-key-id",
        message="Clave de acceso de AWS hardcodeada.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(path="a.py", start_line=3, start_col=6, end_line=3, end_col=26),
        snippet="AKIA****************",
        engine=Engine.regex,
        cwe=["CWE-798"],
        fingerprint="deadbeef",
    )


def test_json_reporter_is_valid_json() -> None:
    output = JSONReporter().render([_finding()], files_scanned=3)
    data = json.loads(output)
    assert data["tool"] == "sastcore"
    assert data["files_scanned"] == 3
    assert data["findings"][0]["rule_id"] == "secrets.aws.access-key-id"
    assert data["findings"][0]["severity"] == "HIGH"


def test_json_reporter_empty() -> None:
    data = json.loads(JSONReporter().render([], files_scanned=0))
    assert data["findings"] == []


def test_console_reporter_no_findings() -> None:
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, width=200)
    ConsoleReporter(console).render([], files_scanned=5)
    assert "Sin hallazgos" in buffer.getvalue()


def test_console_reporter_with_findings() -> None:
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, width=200)
    ConsoleReporter(console).render([_finding()], files_scanned=1)
    output = buffer.getvalue()
    assert "secrets.aws.access-key-id" in output
    assert "hallazgo" in output
