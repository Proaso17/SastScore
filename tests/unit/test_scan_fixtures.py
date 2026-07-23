"""Integración: escaneo de los fixtures 'dirty' y 'clean' (criterio de aceptación F1)."""

from __future__ import annotations

from pathlib import Path

from sastcore.engine.scheduler import Scheduler

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_dirty_fixture_reports_planted_secrets() -> None:
    result = Scheduler().run(_FIXTURES / "dirty")
    ids = {finding.rule_id for finding in result.findings}
    expected = {
        "secrets.aws.access-key-id",
        "secrets.github.token",
        "secrets.google.api-key",
        "secrets.slack.token",
        "secrets.private-key.pem",
        "secrets.db.connection-string",
        "secrets.jwt",
    }
    assert expected <= ids, f"faltan detectores: {expected - ids}"
    assert result.files_scanned > 0


def test_clean_fixture_has_no_findings() -> None:
    result = Scheduler().run(_FIXTURES / "clean")
    assert result.findings == [], [f.rule_id for f in result.findings]
