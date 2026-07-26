"""Interfaz de línea de comandos de sastcore."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from sastcore import __version__
from sastcore._logging import configure_logging
from sastcore.config import (
    CONFIG_FILENAME,
    Config,
    ConfigError,
    OutputFormat,
    default_config_yaml,
    find_config,
    load_config,
)
from sastcore.engine.pattern.pass_ import default_pattern_pass
from sastcore.engine.scheduler import Scheduler
from sastcore.engine.taint.pass_ import default_taint_pass
from sastcore.exit_codes import ExitCode
from sastcore.findings.baseline import Baseline, filter_new
from sastcore.findings.cache import FindingsCache, config_hash
from sastcore.findings.dedup import deduplicate
from sastcore.findings.model import Finding, Severity, confidence_rank, severity_rank
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


def _load_config(no_config: bool) -> Config:
    if no_config:
        return Config()
    path = find_config(Path.cwd())
    if path is None:
        return Config()
    try:
        return load_config(path)
    except ConfigError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(ExitCode.ERROR) from exc


def _apply_config_filters(findings: list[Finding], config: Config) -> list[Finding]:
    disabled = set(config.disabled_rules)
    result = [finding for finding in findings if finding.rule_id not in disabled]
    if config.min_confidence is not None:
        threshold = confidence_rank(config.min_confidence)
        result = [f for f in result if confidence_rank(f.confidence) <= threshold]
    return result


def _scan_targets(scheduler: Scheduler, targets: list[Path]) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    files_scanned = 0
    for target in targets:
        if target.is_dir():
            result = scheduler.run(target)
        elif target.is_file():
            # Se conserva la ruta tal como se pidió (no solo el nombre): así escanear
            # ficheros sueltos reporta la misma ruta que escanear su directorio.
            rel = None if target.is_absolute() else target.as_posix()
            result = scheduler.run_file(target, rel_path=rel)
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
        OutputFormat | None,
        typer.Option("--format", "-f", help="Formato de salida (default: console)."),
    ] = None,
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
    no_config: Annotated[
        bool, typer.Option("--no-config", help="Ignora el fichero .sastcore.yml.")
    ] = False,
) -> None:
    """Escanea código en busca de secretos, patrones y flujos de taint."""
    targets = paths if paths else [Path()]
    config = _load_config(no_config)

    resolved_format = output_format or config.format or OutputFormat.console
    resolved_fail_on = fail_on if fail_on is not None else config.fail_on

    cache = (
        None if no_cache else FindingsCache(Path.cwd(), config=config_hash(default_rulepacks_dir()))
    )
    scheduler = Scheduler(
        pattern_pass=default_pattern_pass(),
        taint_pass=default_taint_pass(),
        cache=cache,
        extra_ignores=config.exclude,
    )
    findings, files_scanned = _scan_targets(scheduler, targets)
    findings = _apply_config_filters(findings, config)

    if baseline is not None:
        if not baseline.is_file():
            console.print(f"[red]Baseline no encontrado:[/red] {baseline}")
            raise typer.Exit(ExitCode.ERROR)
        findings = filter_new(findings, Baseline.load(baseline))

    if resolved_format is OutputFormat.console:
        ConsoleReporter(console).render(findings, files_scanned=files_scanned)
    else:
        text = _text_reporter(resolved_format).render(findings, files_scanned=files_scanned)
        if output is not None:
            output.write_text(text, encoding="utf-8")
            console.print(f"[dim]Informe {resolved_format.value} escrito en {output}.[/dim]")
        else:
            print(text)

    raise typer.Exit(_exit_code(findings, resolved_fail_on))


@app.command()
def init(
    force: Annotated[
        bool, typer.Option("--force", help="Sobrescribe el fichero si ya existe.")
    ] = False,
) -> None:
    """Genera un fichero de configuración .sastcore.yml en el directorio actual."""
    path = Path.cwd() / CONFIG_FILENAME
    if path.exists() and not force:
        console.print(
            f"[yellow]{CONFIG_FILENAME} ya existe. Usa --force para sobrescribir.[/yellow]"
        )
        raise typer.Exit(ExitCode.ERROR)
    path.write_text(default_config_yaml(), encoding="utf-8")
    console.print(f"Configuración escrita en {path}.")
    raise typer.Exit(ExitCode.OK)


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
def serve(
    host: Annotated[str, typer.Option(help="Host de escucha.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Puerto.")] = 8000,
) -> None:
    """Arranca la aplicación web (requiere el extra: pip install 'sastcore[web]')."""
    try:
        import uvicorn
    except ImportError as exc:
        console.print("[red]Falta el extra web.[/red] Instala con: pip install 'sastcore[web]'")
        raise typer.Exit(ExitCode.ERROR) from exc
    console.print(f"sastcore web en [bold]http://{host}:{port}[/bold] (Ctrl+C para parar)")
    uvicorn.run("sastcore.web.app:app", host=host, port=port)


@app.command()
def version() -> None:
    """Muestra la versión de sastcore."""
    console.print(f"sastcore {__version__}")
