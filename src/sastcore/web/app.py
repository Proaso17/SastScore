"""Aplicación web FastAPI: subir código y ver las vulnerabilidades.

Endurecida para producción (Cloud Run): cabeceras de seguridad + CSP estricta,
límite de concurrencia por instancia y un rate-limit por IP best-effort. El
escaneo real corre en un subproceso aislado (ver ``scanning.py``).
"""

from __future__ import annotations

import asyncio
import os
import time
from collections import deque
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from sastcore import __version__
from sastcore.web.scanning import ScanReport, UploadError, prepare_and_scan

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
# Rate-limit por IP: peticiones de escaneo permitidas por ventana de 60 s.
RATE_LIMIT_PER_MIN = _int_env("SASTCORE_RATE_LIMIT_PER_MIN", 20)
_RATE_WINDOW_S = 60.0

_scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
_rate_hits: dict[str, deque[float]] = {}

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_SCAN_PATHS = frozenset({"/scan", "/api/scan"})

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


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _rate_limited(ip: str) -> bool:
    """Sliding-window por IP, en memoria y por instancia (best-effort)."""
    now = time.monotonic()
    hits = _rate_hits.setdefault(ip, deque())
    while hits and now - hits[0] > _RATE_WINDOW_S:
        hits.popleft()
    if len(hits) >= RATE_LIMIT_PER_MIN:
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


@app.middleware("http")
async def _harden(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    if (
        request.method == "POST"
        and request.url.path in _SCAN_PATHS
        and _rate_limited(_client_ip(request))
    ):
        message = "Demasiadas peticiones. Espera un momento y reinténtalo."
        response: Response = (
            JSONResponse({"error": message}, status_code=429)
            if request.url.path == "/api/scan"
            else PlainTextResponse(message, status_code=429)
        )
        return _with_security_headers(response, request)
    return _with_security_headers(await call_next(request), request)


async def _collect(files: list[UploadFile]) -> list[tuple[str, bytes]]:
    return [(file.filename or "upload", await file.read()) for file in files]


async def _run_scan(uploads: list[tuple[str, bytes]]) -> ScanReport:
    """Ejecuta el escaneo respetando el tope de concurrencia de la instancia."""
    async with _scan_semaphore:
        return await asyncio.to_thread(prepare_and_scan, uploads)


@app.get("/")
async def index(request: Request) -> Response:
    return templates.TemplateResponse(
        request, "index.html", {"version": __version__, "asset_ver": ASSET_VER}
    )


@app.post("/scan")
async def scan(request: Request, files: Annotated[list[UploadFile], File()]) -> Response:
    uploads = await _collect(files)
    try:
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
    uploads = await _collect(files)
    try:
        report = await _run_scan(uploads)
    except UploadError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse({"files_scanned": report.files_scanned, "findings": report.findings})


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
