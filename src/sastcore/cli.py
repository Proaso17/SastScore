"""Interfaz de línea de comandos de sastcore."""

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
from sastcore.findings.baseline import Baseline, filter_new
from sastcore.findings.cache import FindingsCache, config_hash
from sastcore.findings.dedup import deduplicate
from sastcore.findings.model import Finding, Severity, severity_rank
from sastcore.reporters.base import TextReporter
from sastcore.reporters.console import ConsoleReporter
from sastcore.reporters.html import HTMLReporter
from sastcore.reporters.json_ import JSONReporter
from sastcore.reporters.junit import JUnitReporter
from sastcore.reporters.markdown import MarkdownReporter
from sastcore.reporters.sarif import SARIFReporter
from sastcore.rules.loader import default_rulepacks_dir

console = Console()

app = typer.Typer(
    name="sastcore",
    help="Motor SAST open-core, multi-lenguaje, orientado a CI/CD.",
    no_args_is_help=True,
    add_completion=False,
)

rules_app = typer.Typer(help="Inspeccionar y gestionar reglas.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")

baseline_app = typer.Typer(help="Gestionar el baseline (modo diferencial).", no_args_is_help=True)
app.add_typer(baseline_app, name="baseline")


class OutputFormat(StrEnum):
    """Formatos de salida soportados por ``scan``."""

    console = "console"
    json = "json"
    sarif = "sarif"
    html = "html"
    markdown = "markdown"
    junit = "junit"


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


def _text_reporter(output_format: OutputFormat) -> TextReporter:
    if output_format is OutputFormat.json:
        return JSONReporter()
    if output_format is OutputFormat.sarif:
        return SARIFReporter()
    if output_format is OutputFormat.html:
        return HTMLReporter()
    if output_format is OutputFormat.markdown:
        return MarkdownReporter()
    return JUnitReporter()


def _scan_targets(scheduler: Scheduler, targets: list[Path]) -> tuple[list[Finding], int]:
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
    return deduplicate(findings), files_scanned


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
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", "-o", help="Escribe el informe a un fichero (formatos no-consola)."
        ),
    ] = None,
    fail_on: Annotated[
        Severity | None,
        typer.Option("--fail-on", help="Severidad mínima que provoca salida distinta de cero."),
    ] = None,
    baseline: Annotated[
        Path | None,
        typer.Option("--baseline", help="Snapshot previo; solo se reportan hallazgos nuevos."),
    ] = None,
    no_cache: Annotated[
        bool, typer.Option("--no-cache", help="Desactiva la cache incremental de hallazgos.")
    ] = False,
) -> None:
    """Escanea código en busca de secretos, patrones y flujos de taint."""
    targets = paths if paths else [Path()]

    cache = (
        None if no_cache else FindingsCache(Path.cwd(), config=config_hash(default_rulepacks_dir()))
    )
    scheduler = Scheduler(
        pattern_pass=default_pattern_pass(), taint_pass=default_taint_pass(), cache=cache
    )
    findings, files_scanned = _scan_targets(scheduler, targets)

    if baseline is not None:
        if not baseline.is_file():
            console.print(f"[red]Baseline no encontrado:[/red] {baseline}")
            raise typer.Exit(ExitCode.ERROR)
        findings = filter_new(findings, Baseline.load(baseline))

    if output_format is OutputFormat.console:
        ConsoleReporter(console).render(findings, files_scanned=files_scanned)
    else:
        text = _text_reporter(output_format).render(findings, files_scanned=files_scanned)
        if output is not None:
            output.write_text(text, encoding="utf-8")
            console.print(f"[dim]Informe {output_format.value} escrito en {output}.[/dim]")
        else:
            print(text)

    raise typer.Exit(_exit_code(findings, fail_on))


@baseline_app.command("create")
def baseline_create(
    paths: Annotated[
        list[Path] | None,
        typer.Argument(help="Ficheros o directorios a escanear."),
    ] = None,
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Fichero de baseline a escribir."),
    ] = Path(".sastcore-baseline.json"),
) -> None:
    """Crea un baseline con los fingerprints del escaneo actual."""
    targets = paths if paths else [Path()]
    scheduler = Scheduler(pattern_pass=default_pattern_pass(), taint_pass=default_taint_pass())
    findings, _ = _scan_targets(scheduler, targets)
    Baseline.from_findings(findings).save(output)
    console.print(f"Baseline con {len(findings)} fingerprint(s) escrito en {output}.")
    raise typer.Exit(ExitCode.OK)


@rules_app.command("list")
def rules_list() -> None:
    """Lista las reglas cargadas."""
    from sastcore.rules.loader import load_rulepacks

    rulepacks = default_rulepacks_dir()
    rules = load_rulepacks(rulepacks, fixtures_root=rulepacks, require_fixtures=False)
    console.print(f"{len(rules)} regla(s) cargada(s) (+ detectores de secretos).")
    raise typer.Exit(ExitCode.OK)


@app.command()
def version() -> None:
    """Muestra la versión de sastcore."""
    console.print(f"sastcore {__version__}")
