"""Tests del modelo Finding y utilidades de severidad."""

from __future__ import annotations

from sastcore.findings.model import (
    Confidence,
    Engine,
    Finding,
    Location,
    Severity,
    severity_rank,
)


def _finding(path: str = "a.py", line: int = 1) -> Finding:
    return Finding(
        rule_id="secrets.aws.access-key-id",
        message="msg",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(path=path, start_line=line, start_col=0, end_line=line, end_col=10),
        snippet="snippet",
        engine=Engine.regex,
    )


def test_serializes_to_json_dict() -> None:
    data = _finding().model_dump(mode="json")
    assert data["severity"] == "HIGH"
    assert data["engine"] == "regex"
    assert data["location"]["start_line"] == 1
    assert data["cwe"] == []
    assert data["data_flow"] == []


def test_severity_rank_is_ordered() -> None:
    assert severity_rank(Severity.CRITICAL) < severity_rank(Severity.HIGH)
    assert severity_rank(Severity.HIGH) < severity_rank(Severity.MEDIUM)
    assert severity_rank(Severity.MEDIUM) < severity_rank(Severity.LOW)
    assert severity_rank(Severity.LOW) < severity_rank(Severity.INFO)


def test_sort_key() -> None:
    assert _finding("b.py", 3).sort_key() > _finding("a.py", 99).sort_key()
