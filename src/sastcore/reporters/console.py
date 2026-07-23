"""Reporter de consola (TTY con colores por severidad)."""

from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.table import Table

from sastcore.findings.model import SEVERITY_ORDER, Finding, Severity

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


class ConsoleReporter:
    """Imprime los hallazgos como una tabla legible en la terminal."""

    def __init__(self, console: Console | None = None) -> None:
        self._console = console if console is not None else Console()

    def render(self, findings: list[Finding], *, files_scanned: int) -> None:
        if not findings:
            self._console.print(
                f"[green]✓[/green] Sin hallazgos. {files_scanned} fichero(s) escaneado(s)."
            )
            return

        table = Table(show_lines=False, expand=False)
        table.add_column("Sev", no_wrap=True)
        table.add_column("Regla", no_wrap=True)
        table.add_column("Ubicación", no_wrap=True)
        table.add_column("Mensaje")

        for finding in findings:
            style = _SEVERITY_STYLE.get(finding.severity, "")
            location = f"{finding.location.path}:{finding.location.start_line}"
            table.add_row(
                f"[{style}]{finding.severity.value}[/{style}]",
                finding.rule_id,
                location,
                finding.message,
            )

        self._console.print(table)
        self._console.print(self._summary(findings, files_scanned=files_scanned))

    @staticmethod
    def _summary(findings: list[Finding], *, files_scanned: int) -> str:
        counts = Counter(finding.severity for finding in findings)
        parts = [f"{counts[sev]} {sev.value}" for sev in SEVERITY_ORDER if counts[sev]]
        breakdown = ", ".join(parts)
        return (
            f"\n[bold]{len(findings)} hallazgo(s)[/bold]: {breakdown} · "
            f"{files_scanned} fichero(s) escaneado(s)."
        )
