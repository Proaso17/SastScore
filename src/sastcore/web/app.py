"""Aplicación web FastAPI: subir código y ver las vulnerabilidades.

Endurecida para producción (Cloud Run): cabeceras de seguridad + CSP estricta,
límite de concurrencia por instancia y un rate-limit por IP best-effort. El
escaneo real corre en un subproceso aislado (ver ``scanning.py``).
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, ValidationError

from sastcore import __version__
from sastcore.findings.model import Finding
from sastcore.reporters.base import TextReporter
from sastcore.reporters.html import HTMLReporter
from sastcore.reporters.json_ import JSONReporter
from sastcore.reporters.markdown import MarkdownReporter
from sastcore.reporters.sarif import SARIFReporter
from sastcore.web.reports_store import build_store
from sastcore.web.scanning import (
    MAX_FILES,
    MAX_UPLOAD_BYTES,
    ScanReport,
    UploadError,
    prepare_and_scan,
    prepare_and_scan_from_github,
)

logger = logging.getLogger(__name__)

_HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_HERE / "templates"))


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _asset_version() -> str:
    """Token de cache-busting: cambia cuando cambian los ficheros static."""
    mtimes = [p.stat().st_mtime for p in (_HERE / "static").glob("*") if p.is_file()]
    return str(int(max(mtimes, default=0)))


ASSET_VER = _asset_version()

# ── Límites operativos (configurables por entorno) ──────────────────────────
# Nº de escaneos pesados simultáneos por instancia (cada uno lanza un subproceso).
MAX_CONCURRENT_SCANS = _int_env("SASTCORE_MAX_CONCURRENT_SCANS", 2)
# Rate-limit por IP y minuto para peticiones baratas (informes, feedback, compartir).
RATE_LIMIT_PER_MIN = _int_env("SASTCORE_RATE_LIMIT_PER_MIN", 20)
# Los escaneos consumen CPU durante segundos, así que llevan una cuota aparte y más
# estrecha: sin esto, 20 escaneos/minuto por IP bastan para saturar la instancia.
RATE_LIMIT_SCANS_PER_MIN = _int_env("SASTCORE_RATE_LIMIT_SCANS_PER_MIN", 5)
# Escaneos simultáneos por IP: evita que un solo cliente ocupe todas las plazas.
MAX_SCANS_PER_IP = _int_env("SASTCORE_MAX_SCANS_PER_IP", 1)
_RATE_WINDOW_S = 60.0
# Nº de proxies de confianza entre el cliente y nosotros (Cloud Run = 1: el GFE).
# El proxy de confianza añade la IP real del cliente por la DERECHA del
# X-Forwarded-For; la parte izquierda la puede falsificar el cliente.
TRUSTED_PROXY_HOPS = _int_env("SASTCORE_TRUSTED_PROXY_HOPS", 1)
# Horas que vive un informe compartido antes de autoexpirar.
REPORT_TTL_HOURS = _int_env("SASTCORE_REPORT_TTL_HOURS", 168)

_scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
_rate_hits: dict[str, deque[float]] = {}
# Escaneos en vuelo por IP (para MAX_SCANS_PER_IP).
_scans_in_flight: dict[str, int] = {}
# Almacén de informes compartibles (opt-in): fichero en local, GCS en producción.
report_store = build_store()

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_SCAN_PATHS = frozenset({"/scan", "/api/scan", "/api/scan-url"})
# Los rule_id son de la forma "py.taint.sql-injection": lista blanca estricta, que
# además evita inyectar saltos de línea u otro ruido en el log al registrarlos.
_RULE_ID_RE = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")

# Descarga de informes: formato -> (reporter, media-type, nombre de fichero).
_REPORTERS: dict[str, tuple[TextReporter, str, str]] = {
    "json": (JSONReporter(), "application/json", "sastcore-report.json"),
    "sarif": (SARIFReporter(), "application/json", "sastcore-report.sarif"),
    "markdown": (MarkdownReporter(), "text/markdown; charset=utf-8", "sastcore-report.md"),
    "html": (HTMLReporter(), "text/html; charset=utf-8", "sastcore-report.html"),
}


class ReportRequest(BaseModel):
    """Cuerpo de /report: los hallazgos que el navegador ya tiene, para reformatearlos."""

    files_scanned: int = 0
    findings: list[dict[str, Any]] = Field(default_factory=list)


class ScanUrlRequest(BaseModel):
    """Cuerpo de /api/scan-url: la URL del repo público de GitHub a analizar."""

    url: str


class FeedbackRequest(BaseModel):
    """Cuerpo de /api/feedback: señal de que una regla dio un falso positivo.

    A propósito **no** se acepta código ni rutas: solo el identificador de la regla.
    Así la señal sirve para mejorar las reglas sin recibir nada del proyecto del
    usuario (ver la promesa de privacidad en /legal).
    """

    rule_id: str = Field(max_length=120)


# Cabeceras de seguridad. La app es autocontenida (sin CDN), así que la CSP puede
# ser estricta: solo scripts/imágenes del propio origen.
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'"
)
_SECURITY_HEADERS = {
    "Content-Security-Policy": _CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}

# En producción no exponemos la documentación interactiva (menos superficie).
app = FastAPI(
    title="sastcore",
    version=__version__,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")


def _pick_client_ip(forwarded: str | None, peer: str | None) -> str:
    """IP del cliente resistente a falsificación de X-Forwarded-For.

    Toma la IP situada ``TRUSTED_PROXY_HOPS`` posiciones desde el final: la que
    añadió el proxy de confianza. Coger la primera (como hacíamos) permitía al
    cliente falsear su IP y saltarse el rate-limit inyectando su propio XFF.
    """
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            return parts[max(0, len(parts) - TRUSTED_PROXY_HOPS)]
    return peer or "unknown"


def _client_ip(request: Request) -> str:
    peer = request.client.host if request.client else None
    return _pick_client_ip(request.headers.get("x-forwarded-for"), peer)


def _rate_limited(ip: str, *, bucket: str = "cheap", limit: int | None = None) -> bool:
    """Sliding-window por IP y ``bucket``, en memoria y por instancia (best-effort).

    Hay cubos separados porque no todas las peticiones cuestan lo mismo: un escaneo
    ocupa CPU durante segundos y un informe es casi gratis.
    """
    allowed = RATE_LIMIT_PER_MIN if limit is None else limit
    now = time.monotonic()
    hits = _rate_hits.setdefault(f"{bucket}:{ip}", deque())
    while hits and now - hits[0] > _RATE_WINDOW_S:
        hits.popleft()
    if len(hits) >= allowed:
        return True
    hits.append(now)
    if len(_rate_hits) > 10_000:  # poda defensiva: evita crecimiento ilimitado
        _rate_hits.clear()
    return False


def _with_security_headers(response: Response, request: Request) -> Response:
    for key, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(key, value)
    # HSTS solo cuando la conexión del cliente es HTTPS; en local (http) no aplica.
    if request.url.scheme == "https":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
        )
    return response


def _wants_json(request: Request) -> bool:
    path = request.url.path
    return path.startswith("/api/") or path.startswith("/report/")


def _error_response(request: Request, status_code: int, message: str) -> Response:
    """JSON para los endpoints de API, texto plano para el resto."""
    response: Response
    if _wants_json(request):
        response = JSONResponse({"error": message}, status_code=status_code)
    else:
        response = PlainTextResponse(message, status_code=status_code)
    if status_code == 429:  # semántica HTTP correcta: cuándo puede reintentar
        response.headers["Retry-After"] = str(int(_RATE_WINDOW_S))
    return response


def _is_scan_post(request: Request) -> bool:
    """POST que lanza un análisis (caro: CPU durante segundos)."""
    return request.method == "POST" and request.url.path in _SCAN_PATHS


def _is_guarded_post(request: Request) -> bool:
    """POST con cuerpo que limitamos por tamaño y frecuencia (scan + report)."""
    if request.method != "POST":
        return False
    path = request.url.path
    return (
        path in _SCAN_PATHS
        or path.startswith("/report/")
        or path in {"/api/share", "/api/feedback"}
    )


def _declared_length_exceeds(request: Request) -> bool:
    """Rechazo temprano por Content-Length antes de bufferear el cuerpo."""
    declared = request.headers.get("content-length")
    return bool(declared and declared.isdigit() and int(declared) > MAX_UPLOAD_BYTES)


async def _dispatch(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    if not _is_guarded_post(request):
        return await call_next(request)

    if _declared_length_exceeds(request):
        limit_mb = MAX_UPLOAD_BYTES // (1024 * 1024)
        return _error_response(request, 413, f"La subida excede el máximo ({limit_mb} MB).")

    ip = _client_ip(request)
    too_many = "Demasiadas peticiones. Espera un momento y reinténtalo."
    if not _is_scan_post(request):
        if _rate_limited(ip):
            return _error_response(request, 429, too_many)
        return await call_next(request)

    # Escaneos: cuota propia más estrecha y un tope de simultáneos por IP.
    if _rate_limited(ip, bucket="scan", limit=RATE_LIMIT_SCANS_PER_MIN):
        return _error_response(request, 429, too_many)
    if _scans_in_flight.get(ip, 0) >= MAX_SCANS_PER_IP:
        return _error_response(
            request, 429, "Ya tienes un análisis en curso. Espera a que termine."
        )
    _scans_in_flight[ip] = _scans_in_flight.get(ip, 0) + 1
    try:
        return await call_next(request)
    finally:
        remaining = _scans_in_flight.get(ip, 1) - 1
        if remaining > 0:
            _scans_in_flight[ip] = remaining
        else:
            _scans_in_flight.pop(ip, None)


@app.middleware("http")
async def _harden(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    # Id de petición para correlacionar logs/errores (se propaga si viene del cliente).
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
    response = await _dispatch(request, call_next)
    response.headers.setdefault("X-Request-ID", request_id)
    return _with_security_headers(response, request)


async def _collect(files: list[UploadFile]) -> list[tuple[str, bytes]]:
    if len(files) > MAX_FILES:
        raise UploadError(f"demasiados ficheros en la subida (máx. {MAX_FILES})")
    return [(file.filename or "upload", await file.read()) for file in files]


async def _run_scan(uploads: list[tuple[str, bytes]]) -> ScanReport:
    """Ejecuta el escaneo respetando el tope de concurrencia de la instancia."""
    async with _scan_semaphore:
        return await asyncio.to_thread(prepare_and_scan, uploads)


async def _run_scan_from_github(url: str) -> ScanReport:
    """Descarga y escanea un repo de GitHub respetando el tope de concurrencia."""
    async with _scan_semaphore:
        return await asyncio.to_thread(prepare_and_scan_from_github, url)


@app.get("/")
async def index(request: Request) -> Response:
    return templates.TemplateResponse(
        request, "index.html", {"version": __version__, "asset_ver": ASSET_VER}
    )


@app.get("/legal")
async def legal(request: Request) -> Response:
    return templates.TemplateResponse(
        request, "legal.html", {"version": __version__, "asset_ver": ASSET_VER}
    )


@app.post("/scan")
async def scan(request: Request, files: Annotated[list[UploadFile], File()]) -> Response:
    try:
        uploads = await _collect(files)
        report = await _run_scan(uploads)
    except UploadError as exc:
        return templates.TemplateResponse(
            request,
            "index.html",
            {"version": __version__, "asset_ver": ASSET_VER, "error": str(exc)},
            status_code=400,
        )
    counts: dict[str, int] = dict.fromkeys(_SEVERITY_ORDER, 0)
    for finding in report.findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return templates.TemplateResponse(
        request,
        "results.html",
        {
            "version": __version__,
            "asset_ver": ASSET_VER,
            "findings": report.findings,
            "files_scanned": report.files_scanned,
            "counts": counts,
            "severity_order": _SEVERITY_ORDER,
        },
    )


@app.post("/api/scan")
async def api_scan(files: Annotated[list[UploadFile], File()]) -> JSONResponse:
    try:
        uploads = await _collect(files)
        report = await _run_scan(uploads)
    except UploadError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse({"files_scanned": report.files_scanned, "findings": report.findings})


@app.post("/api/scan-url")
async def api_scan_url(payload: ScanUrlRequest) -> JSONResponse:
    try:
        report = await _run_scan_from_github(payload.url)
    except UploadError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse({"files_scanned": report.files_scanned, "findings": report.findings})


@app.post("/report/{fmt}")
async def download_report(fmt: str, payload: ReportRequest) -> Response:
    """Reformatea (sin estado) los hallazgos que envía el navegador a un formato descargable."""
    entry = _REPORTERS.get(fmt)
    if entry is None:
        return JSONResponse({"error": "formato de informe no soportado"}, status_code=400)
    reporter, media_type, filename = entry
    try:
        findings = _validated_findings(payload.findings)
    except ValidationError:
        return JSONResponse({"error": "datos de hallazgos inválidos"}, status_code=400)
    text = reporter.render(findings, files_scanned=payload.files_scanned)
    return Response(
        content=text,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _validated_findings(raw: list[dict[str, Any]]) -> list[Finding]:
    """Reconstruye los hallazgos, rechazando cualquier payload que no case con el modelo."""
    return [Finding.model_validate(item) for item in raw]


@app.post("/api/feedback")
async def report_false_positive(payload: FeedbackRequest) -> JSONResponse:
    """Registra que una regla produjo un falso positivo.

    Se anota en el log del servidor (lo recoge Cloud Logging) en vez de guardarlo en
    una base de datos: basta para saber qué reglas fallan y no añade estado ni
    almacena nada del usuario.
    """
    rule_id = payload.rule_id.strip()
    if not _RULE_ID_RE.match(rule_id):
        return JSONResponse({"error": "identificador de regla no válido"}, status_code=400)
    logger.warning("feedback: falso positivo reportado para la regla %s", rule_id)
    return JSONResponse({"status": "ok"})


@app.post("/api/share")
async def share_report(payload: ReportRequest) -> JSONResponse:
    """Guarda el informe (opt-in) y devuelve el enlace efímero para compartirlo."""
    try:
        findings = _validated_findings(payload.findings)
    except ValidationError:
        return JSONResponse({"error": "datos de hallazgos inválidos"}, status_code=400)
    stored = {
        "files_scanned": payload.files_scanned,
        "findings": [finding.model_dump(mode="json") for finding in findings],
    }
    try:
        report_id = await asyncio.to_thread(report_store.save, stored)
    except Exception:
        logger.exception("no se pudo guardar el informe compartido")
        return JSONResponse({"error": "no se pudo crear el enlace"}, status_code=503)
    return JSONResponse({"id": report_id, "url": f"/r/{report_id}", "ttl_hours": REPORT_TTL_HOURS})


@app.get("/r/{report_id}")
async def view_shared_report(request: Request, report_id: str) -> Response:
    """Muestra un informe compartido; 404 si no existe o ya caducó."""
    try:
        stored = await asyncio.to_thread(report_store.load, report_id)
    except Exception:
        logger.exception("no se pudo leer el informe compartido")
        stored = None
    if stored is None:
        return templates.TemplateResponse(
            request,
            "expired.html",
            {"version": __version__, "asset_ver": ASSET_VER},
            status_code=404,
        )
    findings = list(stored.get("findings", []))
    counts: dict[str, int] = dict.fromkeys(_SEVERITY_ORDER, 0)
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return templates.TemplateResponse(
        request,
        "results.html",
        {
            "version": __version__,
            "asset_ver": ASSET_VER,
            "findings": findings,
            "files_scanned": int(stored.get("files_scanned", 0)),
            "counts": counts,
            "severity_order": _SEVERITY_ORDER,
            "shared": True,
        },
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
