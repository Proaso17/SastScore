"""Preparación segura de la subida y ejecución aislada del escaneo.

Cada escaneo se ejecuta en un **subproceso** (la CLI ``sastcore scan``): así el servidor
de larga vida no acumula objetos de tree-sitter (que forman ciclos y obligan a desactivar
el GC), y un fallo del análisis queda contenido en su propio proceso.

La extracción del zip está endurecida contra *zip-slip* (rutas fuera del destino),
*zip-bomb* (límite de tamaño descomprimido y nº de ficheros) y symlinks.
"""

from __future__ import annotations

import io
import json
import logging
import os
import stat
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


# Límites configurables por entorno. El tope de subida por defecto (32 MiB) es el
# máximo que admite Cloud Run en una petición; súbelo solo si tu plataforma lo permite.
MAX_UPLOAD_BYTES = _int_env("SASTCORE_MAX_UPLOAD_BYTES", 32 * 1024 * 1024)
MAX_UNCOMPRESSED_BYTES = _int_env("SASTCORE_MAX_UNCOMPRESSED_BYTES", 200 * 1024 * 1024)
MAX_FILES = _int_env("SASTCORE_MAX_FILES", 20_000)
SCAN_TIMEOUT_S = _int_env("SASTCORE_SCAN_TIMEOUT_S", 180)
_CHUNK = 1 << 16


class UploadError(ValueError):
    """Subida inválida (zip inseguro, demasiado grande, formato incorrecto)."""


@dataclass
class ScanReport:
    """Resultado del escaneo de una subida."""

    files_scanned: int
    findings: list[dict[str, Any]]


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(info.external_attr >> 16)


def _safe_target(dest: Path, name: str) -> Path:
    """Resuelve el destino garantizando que queda dentro de ``dest`` (anti zip-slip)."""
    target = (dest / name).resolve()
    if target != dest and dest not in target.parents:
        raise UploadError(f"ruta insegura en el zip: {name!r}")
    return target


def extract_zip(data: bytes, dest: Path) -> None:
    """Extrae ``data`` (bytes de un zip) bajo ``dest`` de forma segura."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise UploadError("el fichero no es un zip válido") from exc

    written = 0
    count = 0
    with archive:
        for info in archive.infolist():
            if info.is_dir() or _is_symlink(info):
                continue
            count += 1
            if count > MAX_FILES:
                raise UploadError("el zip contiene demasiados ficheros")
            target = _safe_target(dest, info.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as src, target.open("wb") as out:
                while chunk := src.read(_CHUNK):
                    written += len(chunk)
                    if written > MAX_UNCOMPRESSED_BYTES:
                        raise UploadError("el zip descomprimido excede el límite")
                    out.write(chunk)


def _write_plain_file(dest: Path, filename: str, data: bytes) -> None:
    safe = Path(filename).name or "upload.txt"
    (dest / safe).write_bytes(data)


def scan_directory(root: Path) -> ScanReport:
    """Escanea ``root`` invocando la CLI en un subproceso aislado."""
    # Forzamos UTF-8 en ambos extremos: el hijo escribe UTF-8 (PYTHONIOENCODING/
    # PYTHONUTF8) y el padre lo lee como UTF-8. Así los acentos no dependen del
    # locale de Windows (cp1252), que provoca mojibake ("criptogrÃ¡ficamente").
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    command = [
        sys.executable,
        "-m",
        "sastcore",
        "scan",
        str(root),
        "--format",
        "json",
        "--no-cache",
        "--no-config",
    ]
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=SCAN_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise UploadError("el análisis tardó demasiado y se canceló") from exc
    except OSError as exc:
        logger.warning("no se pudo lanzar el subproceso de escaneo: %s", exc)
        raise UploadError("no se pudo ejecutar el análisis") from exc
    if proc.returncode not in (0, 1):
        # El stderr puede contener rutas internas/trazas: se registra en el
        # servidor, nunca se devuelve al cliente.
        logger.warning("el escaneo salió con código %s: %s", proc.returncode, proc.stderr.strip())
        raise UploadError("el análisis falló al procesar la subida")
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise UploadError("la salida del escaneo no es válida") from exc
    return ScanReport(
        files_scanned=int(payload.get("files_scanned", 0)),
        findings=list(payload.get("findings", [])),
    )


def prepare_and_scan(uploads: list[tuple[str, bytes]]) -> ScanReport:
    """Prepara un espacio de trabajo temporal desde la subida y lo escanea."""
    if not uploads:
        raise UploadError("no se subió ningún fichero")
    if sum(len(data) for _, data in uploads) > MAX_UPLOAD_BYTES:
        limit_mb = MAX_UPLOAD_BYTES // (1024 * 1024)
        raise UploadError(f"la subida excede el tamaño máximo ({limit_mb} MB)")

    with tempfile.TemporaryDirectory(prefix="sastcore_web_") as tmp:
        dest = Path(tmp).resolve()
        for filename, data in uploads:
            if filename.lower().endswith(".zip"):
                extract_zip(data, dest)
            else:
                _write_plain_file(dest, filename, data)
        return scan_directory(dest)
