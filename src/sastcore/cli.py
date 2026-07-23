"""Interfaz de línea de comandos de sastcore.

Fase 0: la superficie de comandos y flags queda congelada aquí para que los
scripts de CI puedan depender de ella, pero el motor de análisis todavía no
existe. Los comandos son deliberadamente stubs.
"""

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from sastcore import __version__
from sastcore._logging import configure_logging
from sastcore.exit_codes import ExitCode

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


class Severity(StrEnum):
    """Niveles de severidad, de mayor a menor."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"sastcore {__version__}")
        raise typer.Exit(ExitCode.OK)


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
    """Escanea código en busca de vulnerabilidades.

    Fase 0: esqueleto. Acepta y valida los argumentos, pero aún no hay motor de
    análisis; siempre termina con :data:`ExitCode.OK`.
    """
    targets = paths if paths else [Path()]
    # Flags declarados para congelar la superficie CLI; sin efecto en la Fase 0.
    _ = (output_format, fail_on, baseline)
    console.print(
        f"[dim]sastcore {__version__}: 0 reglas cargadas · {len(targets)} objetivo(s) · "
        "esqueleto de Fase 0, motor no implementado todavía.[/dim]"
    )
    raise typer.Exit(ExitCode.OK)


@rules_app.command("list")
def rules_list() -> None:
    """Lista las reglas cargadas. Fase 0: aún no hay rulepacks."""
    console.print("0 reglas disponibles (los rulepacks llegan en la Fase 3).")
    raise typer.Exit(ExitCode.OK)


@app.command()
def version() -> None:
    """Muestra la versión de sastcore."""
    console.print(f"sastcore {__version__}")
