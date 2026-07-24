"""Interfaz común de los reporters."""

from __future__ import annotations

from typing import Protocol

from sastcore.findings.model import Finding


class Reporter(Protocol):
    """Un reporter renderiza una lista de hallazgos.

    ``render`` devuelve el texto del informe (p. ej. JSON) o ``None`` si el reporter
    escribe directamente en su propio sink (p. ej. la consola).
    """

    def render(self, findings: list[Finding], *, files_scanned: int) -> str | None: ...


class TextReporter(Protocol):
    """Reporter que devuelve el informe como texto (JSON, SARIF, HTML, Markdown, JUnit)."""

    def render(self, findings: list[Finding], *, files_scanned: int) -> str: ...
