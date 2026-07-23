"""Tests de la deduplicación de hallazgos."""

from __future__ import annotations

from sastcore.findings.dedup import deduplicate
from sastcore.findings.model import Confidence, Engine, Finding, Location, Severity


def _finding(path: str, line: int, fingerprint: str) -> Finding:
    return Finding(
        rule_id="r",
        message="m",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(path=path, start_line=line, start_col=0, end_line=line, end_col=3),
        snippet="s",
        engine=Engine.regex,
        fingerprint=fingerprint,
    )


def test_collapses_same_path_and_fingerprint() -> None:
    findings = [_finding("a.py", 1, "x"), _finding("a.py", 1, "x")]
    assert len(deduplicate(findings)) == 1


def test_keeps_same_fingerprint_in_different_files() -> None:
    findings = [_finding("a.py", 1, "x"), _finding("b.py", 1, "x")]
    assert len(deduplicate(findings)) == 2


def test_deterministic_order() -> None:
    findings = [
        _finding("b.py", 2, "2"),
        _finding("a.py", 5, "5"),
        _finding("a.py", 1, "1"),
    ]
    result = deduplicate(findings)
    assert [(f.location.path, f.location.start_line) for f in result] == [
        ("a.py", 1),
        ("a.py", 5),
        ("b.py", 2),
    ]
