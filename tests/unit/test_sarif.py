"""Tests del reporter SARIF 2.1.0 (validación estructural)."""

from __future__ import annotations

import json

from sastcore.findings.model import (
    Confidence,
    DataFlowStep,
    Engine,
    Finding,
    Location,
    Severity,
)
from sastcore.reporters.sarif import SARIFReporter


def _loc(line: int = 4) -> Location:
    return Location(path="app.py", start_line=line, start_col=2, end_line=line, end_col=20)


def _finding(
    severity: Severity = Severity.HIGH, data_flow: list[DataFlowStep] | None = None
) -> Finding:
    return Finding(
        rule_id="py.taint.sql-injection",
        message="Inyección SQL.",
        severity=severity,
        confidence=Confidence.HIGH,
        location=_loc(),
        snippet="cursor.execute(q)",
        engine=Engine.taint,
        cwe=["CWE-89"],
        owasp="A03:2021-Injection",
        references=["https://cwe.mitre.org/data/definitions/89.html"],
        fingerprint="abc123",
        data_flow=data_flow or [],
    )


def test_sarif_structure() -> None:
    sarif = json.loads(SARIFReporter().render([_finding()], files_scanned=1))
    assert sarif["version"] == "2.1.0"
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "sastcore"
    assert driver["rules"][0]["id"] == "py.taint.sql-injection"
    assert driver["rules"][0]["helpUri"].startswith("https://")
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "py.taint.sql-injection"
    assert result["ruleIndex"] == 0
    assert result["level"] == "error"
    assert result["partialFingerprints"]["sastcore/v1"] == "abc123"
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 4
    assert region["startColumn"] == 3  # 0-indexado + 1


def test_sarif_level_mapping() -> None:
    def level(sev: Severity) -> str:
        sarif = json.loads(SARIFReporter().render([_finding(severity=sev)], files_scanned=1))
        return str(sarif["runs"][0]["results"][0]["level"])

    assert level(Severity.CRITICAL) == "error"
    assert level(Severity.MEDIUM) == "warning"
    assert level(Severity.LOW) == "note"


def test_sarif_codeflows_for_taint() -> None:
    flow = [
        DataFlowStep(location=_loc(2), message="entrada no confiable (source)"),
        DataFlowStep(location=_loc(4), message="llega a un sink peligroso"),
    ]
    sarif = json.loads(SARIFReporter().render([_finding(data_flow=flow)], files_scanned=1))
    result = sarif["runs"][0]["results"][0]
    locations = result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert len(locations) == 2
    assert locations[0]["location"]["message"]["text"] == "entrada no confiable (source)"
    assert locations[-1]["location"]["physicalLocation"]["region"]["startLine"] == 4


def test_sarif_empty() -> None:
    sarif = json.loads(SARIFReporter().render([], files_scanned=0))
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
