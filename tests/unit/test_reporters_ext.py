"""Tests de los reporters HTML, Markdown y JUnit."""

from __future__ import annotations

from xml.etree import ElementTree as ET

from sastcore.findings.model import Confidence, Engine, Finding, Location, Severity
from sastcore.reporters.html import HTMLReporter
from sastcore.reporters.junit import JUnitReporter
from sastcore.reporters.markdown import MarkdownReporter


def _finding(message: str = "Inyección SQL.") -> Finding:
    return Finding(
        rule_id="py.taint.sql-injection",
        message=message,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(path="app.py", start_line=4, start_col=0, end_line=4, end_col=10),
        snippet="cursor.execute(q)",
        engine=Engine.taint,
        fingerprint="abc",
    )


def test_html_is_self_contained() -> None:
    html = HTMLReporter().render([_finding()], files_scanned=1)
    assert "<!doctype html>" in html.lower()
    assert "py.taint.sql-injection" in html
    # Sin recursos externos ni scripts.
    for token in ("src=", "href=", "<link", "<script", "http://", "https://"):
        assert token not in html


def test_html_escapes_content() -> None:
    html = HTMLReporter().render([_finding(message="<script>alert(1)</script>")], files_scanned=1)
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;" in html


def test_markdown_table() -> None:
    md = MarkdownReporter().render([_finding()], files_scanned=1)
    assert "| Sev | Regla | Ubicación | Mensaje |" in md
    assert "`py.taint.sql-injection`" in md


def test_markdown_empty() -> None:
    assert "Sin hallazgos" in MarkdownReporter().render([], files_scanned=3)


def test_junit_is_valid_xml() -> None:
    xml = JUnitReporter().render([_finding()], files_scanned=1)
    root = ET.fromstring(xml)
    assert root.tag == "testsuites"
    testcase = root.find(".//testcase")
    assert testcase is not None
    assert testcase.get("classname") == "py.taint.sql-injection"
    assert testcase.find("failure") is not None
