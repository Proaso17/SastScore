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
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

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
# Ficheros por subproceso (tope inicial). Arrancar un proceso cuesta ~1,5 s y analizar
# un fichero ~0,06 s, así que conviene que quepan muchos ficheros por lote. Si un lote
# muere —el binding de tree-sitter se corrompe tras parsear muchos ficheros en el mismo
# proceso en Windows, ver ADR-0005— el escaneo reduce el tamaño automáticamente, así que
# este valor es solo el punto de partida.
SCAN_BATCH_FILES = _int_env("SASTCORE_SCAN_BATCH_FILES", 200)
# Descarga de repos de GitHub (tarball comprimido) por URL.
MAX_DOWNLOAD_BYTES = _int_env("SASTCORE_MAX_DOWNLOAD_BYTES", 60 * 1024 * 1024)
GITHUB_TIMEOUT_S = _int_env("SASTCORE_GITHUB_TIMEOUT_S", 30)
_CHUNK = 1 << 16

# Validación estricta: solo contactamos hosts de GitHub y la URL la construimos
# nosotros a partir de owner/repo validados (no seguimos la URL cruda del usuario).
_GITHUB_URL = re.compile(r"^https://github\.com/([^/\s]+)/([^/\s#?]+)")
_GH_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_GH_REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_GH_ALLOWED_HOSTS = frozenset({"github.com", "api.github.com", "codeload.github.com"})


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
        raise UploadError(f"ruta insegura en el archivo: {name!r}")
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


def _discover_targets(root: Path) -> list[str]:
    """Rutas relativas a escanear, con las mismas reglas de descubrimiento que la CLI."""
    from sastcore.discovery.walker import FileWalker

    return [rel for _path, rel in FileWalker(root).walk()]


def _scan_batch(root: Path, targets: Sequence[str], timeout_s: float) -> dict[str, Any] | None:
    """Escanea un lote de ficheros en un subproceso; ``None`` si no dio informe usable."""
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    command = [
        sys.executable,
        "-m",
        "sastcore",
        "scan",
        *targets,
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
            cwd=str(root),
            timeout=timeout_s,
            check=False,
        )
    except OSError as exc:
        logger.warning("no se pudo lanzar el subproceso de escaneo: %s", exc)
        raise UploadError("no se pudo ejecutar el análisis") from exc

    # Se mira la SALIDA antes del código de retorno: el informe JSON se emite al
    # final, así que si se parsea completo el lote terminó y sus resultados son
    # fiables aunque el proceso muriera después (el binding de tree-sitter puede
    # provocar un fallo de segmentación al liberar memoria, ver ADR-0005).
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = None
    if not isinstance(payload, dict):
        # El stderr puede llevar rutas internas/trazas: se registra, nunca se devuelve.
        logger.warning(
            "lote sin informe utilizable (código %s, %d fichero(s)): %s",
            proc.returncode,
            len(targets),
            proc.stderr.strip()[:300],
        )
        return None
    if proc.returncode not in (0, 1):
        logger.info(
            "el lote terminó con código %s pero produjo un informe completo; se usa",
            proc.returncode,
        )
    return payload


def scan_directory(root: Path) -> ScanReport:
    """Escanea ``root`` en **lotes**, cada uno en un subproceso aislado.

    El binding de tree-sitter se corrompe tras parsear unas decenas de ficheros en el
    mismo proceso (ADR-0005), así que un único subproceso no basta para un repositorio
    real: se trocea el trabajo y cada lote arranca con un intérprete limpio. Si un lote
    muere sin dar informe se parte en dos y se reintenta, de modo que un solo fichero
    problemático no arruina el análisis completo.
    """
    targets = _discover_targets(root)
    if not targets:
        return ScanReport(files_scanned=0, findings=[])

    deadline = time.monotonic() + SCAN_TIMEOUT_S
    findings: list[dict[str, Any]] = []
    files_scanned = 0
    queue = deque(targets)
    split: list[list[str]] = []  # mitades pendientes de un lote que murió
    # Se empieza con lotes grandes (un proceso arranca en ~1,5 s, así que cuantos
    # menos procesos, mejor) y se reduce el tamaño solo si alguno muere.
    size = SCAN_BATCH_FILES

    while queue or split:
        # Primero las mitades pendientes de un lote que murió; si no, un lote nuevo.
        batch = split.pop(0) if split else [queue.popleft() for _ in range(min(size, len(queue)))]
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise UploadError("el análisis tardó demasiado y se canceló")
        try:
            payload = _scan_batch(root, batch, remaining)
        except subprocess.TimeoutExpired as exc:
            raise UploadError("el análisis tardó demasiado y se canceló") from exc

        if payload is None:
            if len(batch) > 1:
                # Se parte en dos para aislar el fichero problemático y se aprende
                # el tamaño: los lotes siguientes ya salen más pequeños.
                middle = len(batch) // 2
                split[:0] = [batch[:middle], batch[middle:]]
                size = max(1, min(size, middle))
                continue
            logger.warning("se omite un fichero que no se pudo analizar: %s", batch[0])
            continue

        files_scanned += int(payload.get("files_scanned", 0))
        findings.extend(payload.get("findings", []))

    if files_scanned == 0:
        # Había ficheros pero no se pudo analizar ninguno: es un fallo, no un
        # "todo limpio". Devolver un informe vacío haría creer que no hay problemas.
        raise UploadError("el análisis falló al procesar la subida")
    return ScanReport(files_scanned=files_scanned, findings=findings)


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


def parse_github_url(url: str) -> tuple[str, str]:
    """Extrae ``(owner, repo)`` de una URL de GitHub, validándolos estrictamente."""
    match = _GITHUB_URL.match(url.strip())
    if not match:
        raise UploadError("URL no válida. Usa https://github.com/owner/repo")
    owner, repo = match.group(1), match.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not _GH_OWNER.match(owner) or not _GH_REPO.match(repo):
        raise UploadError("nombre de owner o repositorio no válido")
    return owner, repo


def download_github_tarball(owner: str, repo: str) -> bytes:
    """Descarga el tarball de un repo público de GitHub (sin autenticación).

    Solo se contactan hosts de GitHub; la URL la construimos nosotros a partir de
    ``owner``/``repo`` ya validados, con límite de tamaño y timeout. Así no hay SSRF
    hacia hosts arbitrarios ni por la URL cruda del usuario ni por redirecciones.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/tarball"
    buffer = bytearray()
    try:
        with (
            httpx.Client(
                timeout=GITHUB_TIMEOUT_S,
                follow_redirects=True,
                headers={"User-Agent": "sastcore"},
            ) as client,
            client.stream("GET", url) as response,
        ):
            if response.url.host not in _GH_ALLOWED_HOSTS:
                raise UploadError("destino de descarga no permitido")
            if response.status_code == 404:
                raise UploadError("repositorio no encontrado (¿es público?)")
            if response.status_code != 200:
                raise UploadError("no se pudo descargar el repositorio")
            for chunk in response.iter_bytes(_CHUNK):
                buffer.extend(chunk)
                if len(buffer) > MAX_DOWNLOAD_BYTES:
                    raise UploadError("el repositorio es demasiado grande")
    except httpx.HTTPError as exc:
        logger.warning("fallo al descargar %s/%s: %s", owner, repo, exc)
        raise UploadError("no se pudo descargar el repositorio") from exc
    return bytes(buffer)


def extract_tarball(data: bytes, dest: Path) -> None:
    """Extrae un ``tar.gz`` bajo ``dest`` de forma segura (solo ficheros regulares)."""
    written = 0
    count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive:
                # Solo ficheros regulares: ignora dirs, symlinks, hardlinks y devices.
                if not member.isreg():
                    continue
                count += 1
                if count > MAX_FILES:
                    raise UploadError("el repositorio contiene demasiados ficheros")
                written += member.size
                if written > MAX_UNCOMPRESSED_BYTES:
                    raise UploadError("el repositorio descomprimido excede el límite")
                target = _safe_target(dest, member.name)  # anti path-traversal
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    continue
                with source, target.open("wb") as out:
                    shutil.copyfileobj(source, out, _CHUNK)
    except tarfile.TarError as exc:
        raise UploadError("el archivo descargado no es un tar.gz válido") from exc


def prepare_and_scan_from_github(url: str) -> ScanReport:
    """Descarga un repo público de GitHub por URL y lo escanea."""
    owner, repo = parse_github_url(url)
    data = download_github_tarball(owner, repo)
    with tempfile.TemporaryDirectory(prefix="sastcore_gh_") as tmp:
        dest = Path(tmp).resolve()
        extract_tarball(data, dest)
        return scan_directory(dest)
