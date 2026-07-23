"""Tests de la supresión inline sastcore:ignore."""

from __future__ import annotations

from sastcore.findings.model import Confidence, Engine, Finding, Location, Severity
from sastcore.suppression import apply_suppressions


def _finding(rule_id: str, line: int) -> Finding:
    return Finding(
        rule_id=rule_id,
        message="m",
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        location=Location(path="a.py", start_line=line, start_col=0, end_line=line, end_col=1),
        snippet="s",
        engine=Engine.pattern,
    )


def test_inline_suppression() -> None:
    lines = ["os.system(x)  # sastcore:ignore py.dangerous.os-system -- entrada confiable"]
    assert apply_suppressions([_finding("py.dangerous.os-system", 1)], lines) == []


def test_suppression_on_previous_line() -> None:
    lines = ["# sastcore:ignore py.dangerous.eval -- revisado por seguridad", "eval(x)"]
    assert apply_suppressions([_finding("py.dangerous.eval", 2)], lines) == []


def test_reason_is_required() -> None:
    lines = ["eval(x)  # sastcore:ignore py.dangerous.eval"]
    assert len(apply_suppressions([_finding("py.dangerous.eval", 1)], lines)) == 1


def test_only_named_rule_is_suppressed() -> None:
    lines = ["eval(x)  # sastcore:ignore py.other.rule -- motivo"]
    assert len(apply_suppressions([_finding("py.dangerous.eval", 1)], lines)) == 1
