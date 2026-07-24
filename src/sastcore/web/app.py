"""Aplicación web FastAPI: subir código y ver las vulnerabilidades."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from sastcore import __version__
from sastcore.web.scanning import UploadError, prepare_and_scan

_HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_HERE / "templates"))

app = FastAPI(title="sastcore", version=__version__)
app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


async def _collect(files: list[UploadFile]) -> list[tuple[str, bytes]]:
    return [(file.filename or "upload", await file.read()) for file in files]


@app.get("/")
async def index(request: Request) -> Response:
    return templates.TemplateResponse(request, "index.html", {"version": __version__})


@app.post("/scan")
async def scan(request: Request, files: Annotated[list[UploadFile], File()]) -> Response:
    uploads = await _collect(files)
    try:
        report = await asyncio.to_thread(prepare_and_scan, uploads)
    except UploadError as exc:
        return templates.TemplateResponse(
            request, "index.html", {"version": __version__, "error": str(exc)}, status_code=400
        )
    counts: dict[str, int] = dict.fromkeys(_SEVERITY_ORDER, 0)
    for finding in report.findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return templates.TemplateResponse(
        request,
        "results.html",
        {
            "version": __version__,
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
        report = await asyncio.to_thread(prepare_and_scan, uploads)
    except UploadError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse({"files_scanned": report.files_scanned, "findings": report.findings})


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
