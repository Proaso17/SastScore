"""Interfaz de línea de comandos de sastcore.

La superficie de comandos y flags está congelada desde la Fase 0. En la Fase 1,
``scan`` ejecuta discovery + la pasada de secretos y despacha al reporter elegido.
"""

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from sastcore import __version__
from sastcore._logging import configure_logging
from sastcore.engine.pattern.pass_ import default_pattern_pass
from sastcore.engine.scheduler import Scheduler
from sastcore.engine.taint.pass_ import default_taint_pass
from sastcore.exit_codes import ExitCode
from sastcore.findings.dedup import deduplicate
from sastcore.findings.model import Finding, Severity, severity_rank
from sastcore.reporters.console import ConsoleReporter
from sastcore.reporters.json_ import JSONReporter

console = Console()

app = typer.Typer(
    name="sastcore",
    help="Motor SAST open-core, multi-lenguaje, orientado a CI/CD.",
    no_args_is_help=True,
    add_completion=False,
)

rules_app = typer.Typer(help="Inspeccionar y gestionar reglas.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")


class OutputFormat(StrEnum):
    """Formatos de salida soportados por ``scan``."""

    console = "console"
    json = "json"
    sarif = "sarif"


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"sastcore {__version__}")
        raise typer.Exit(ExitCode.OK)


def _exit_code(findings: list[Finding], fail_on: Severity | None) -> ExitCode:
    """Determina el código de salida según el umbral ``--fail-on``."""
    if fail_on is None:
        return ExitCode.OK
    threshold = severity_rank(fail_on)
    if any(severity_rank(finding.severity) <= threshold for finding in findings):
        return ExitCode.FINDINGS
    return ExitCode.OK


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Muestra la versión y sale.",
        ),
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Activa el log de depuración.")
    ] = False,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="Silencia todo salvo los errores.")
    ] = False,
) -> None:
    """sastcore — análisis estático de seguridad del código fuente."""
    configure_logging(verbose=verbose, quiet=quiet)


@app.command()
def scan(
    paths: Annotated[
        list[Path] | None,
        typer.Argument(
            help="Ficheros o directorios a escanear. Por defecto: el directorio actual.",
        ),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Formato de salida."),
    ] = OutputFormat.console,
    fail_on: Annotated[
        Severity | None,
        typer.Option("--fail-on", help="Severidad mínima que provoca salida distinta de cero."),
    ] = None,
    baseline: Annotated[
        Path | None,
        typer.Option("--baseline", help="Snapshot previo; solo se reportan hallazgos nuevos."),
    ] = None,
) -> None:
    """Escanea código en busca de vulnerabilidades (Fase 1: secretos)."""
    targets = paths if paths else [Path()]

    if baseline is not None:
        console.print("[yellow]--baseline aún no está implementado (llega en la Fase 5).[/yellow]")

    scheduler = Scheduler(pattern_pass=default_pattern_pass(), taint_pass=default_taint_pass())
    findings: list[Finding] = []
    files_scanned = 0
    for target in targets:
        if target.is_dir():
            result = scheduler.run(target)
        elif target.is_file():
            result = scheduler.run_file(target)
        else:
            console.print(f"[red]Ruta no encontrada:[/red] {target}")
            raise typer.Exit(ExitCode.ERROR)
        findings.extend(result.findings)
        files_scanned += result.files_scanned

    findings = deduplicate(findings)

    if output_format is OutputFormat.json:
        print(JSONReporter().render(findings, files_scanned=files_scanned))
    elif output_format is OutputFormat.sarif:
        console.print("[yellow]El reporter SARIF llega en la Fase 5.[/yellow]")
        raise typer.Exit(ExitCode.ERROR)
    else:
        ConsoleReporter(console).render(findings, files_scanned=files_scanned)

    raise typer.Exit(_exit_code(findings, fail_on))


@rules_app.command("list")
def rules_list() -> None:
    """Lista las reglas cargadas. Fase 1: solo detectores de secretos, sin rulepacks YAML."""
    console.print("Detectores de secretos activos (los rulepacks YAML llegan en la Fase 3).")
    raise typer.Exit(ExitCode.OK)


@app.command()
def version() -> None:
    """Muestra la versión de sastcore."""
    console.print(f"sastcore {__version__}")
