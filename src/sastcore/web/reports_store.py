"""Almacén de informes compartibles (opt-in y efímero).

Guarda **solo el informe** (los hallazgos que el navegador ya tiene), nunca el árbol
de código completo, con un identificador aleatorio y una caducidad. Dos backends que
se eligen por entorno:

- :class:`FilesystemReportStore`: por defecto (desarrollo local y una sola instancia).
- :class:`GcsReportStore`: producción en Cloud Run (Google Cloud Storage, compartido
  entre instancias), activado con ``SASTCORE_REPORTS_BUCKET``.

El identificador se valida contra una lista blanca de caracteres antes de tocar el
sistema de ficheros o el bucket, así que no hay path-traversal.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)

_ID_RE = re.compile(r"^[A-Za-z0-9_-]{6,64}$")


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _new_id() -> str:
    return secrets.token_urlsafe(12)


def _fresh_payload(record: dict[str, Any]) -> dict[str, Any] | None:
    """Devuelve el informe si no ha caducado; ``None`` en caso contrario."""
    if float(record.get("expires_at", 0)) < time.time():
        return None
    payload = record.get("payload")
    return payload if isinstance(payload, dict) else None


class ReportStore(Protocol):
    """Persiste un informe y lo recupera por su id."""

    def save(self, payload: dict[str, Any]) -> str: ...

    def load(self, report_id: str) -> dict[str, Any] | None: ...


class FilesystemReportStore:
    """Guarda cada informe como un fichero JSON con marca de caducidad."""

    def __init__(self, directory: Path, ttl_s: int) -> None:
        self._dir = directory
        self._ttl_s = ttl_s
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path(self, report_id: str) -> Path:
        return self._dir / f"{report_id}.json"

    def save(self, payload: dict[str, Any]) -> str:
        report_id = _new_id()
        record = {"expires_at": time.time() + self._ttl_s, "payload": payload}
        self._path(report_id).write_text(json.dumps(record), encoding="utf-8")
        self._prune()
        return report_id

    def load(self, report_id: str) -> dict[str, Any] | None:
        if not _ID_RE.match(report_id):
            return None
        path = self._path(report_id)
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        payload = _fresh_payload(record)
        if payload is None:
            path.unlink(missing_ok=True)
        return payload

    def _prune(self) -> None:
        """Borra informes caducados (barato: se llama en cada guardado)."""
        now = time.time()
        for path in self._dir.glob("*.json"):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if float(record.get("expires_at", 0)) < now:
                path.unlink(missing_ok=True)


class GcsReportStore:
    """Guarda cada informe como un objeto en un bucket de Google Cloud Storage."""

    def __init__(self, bucket: str, ttl_s: int) -> None:
        self._bucket_name = bucket
        self._ttl_s = ttl_s
        self._client: Any = None

    def _blob(self, report_id: str) -> Any:
        from google.cloud import storage  # import perezoso: solo si se usa GCS

        if self._client is None:
            self._client = storage.Client()
        return self._client.bucket(self._bucket_name).blob(f"reports/{report_id}.json")

    def save(self, payload: dict[str, Any]) -> str:
        report_id = _new_id()
        record = {"expires_at": time.time() + self._ttl_s, "payload": payload}
        self._blob(report_id).upload_from_string(
            json.dumps(record), content_type="application/json"
        )
        return report_id

    def load(self, report_id: str) -> dict[str, Any] | None:
        if not _ID_RE.match(report_id):
            return None
        blob = self._blob(report_id)
        try:
            data = blob.download_as_bytes()
        except Exception:
            return None
        try:
            record = json.loads(data)
        except json.JSONDecodeError:
            return None
        payload = _fresh_payload(record)
        if payload is None:
            try:
                blob.delete()
            except Exception:
                logger.debug("no se pudo borrar el informe caducado %s", report_id)
        return payload


def build_store() -> ReportStore:
    """Elige el backend según el entorno: GCS si hay bucket, si no, sistema de ficheros."""
    ttl_s = _int_env("SASTCORE_REPORT_TTL_HOURS", 168) * 3600
    bucket = os.environ.get("SASTCORE_REPORTS_BUCKET")
    if bucket:
        return GcsReportStore(bucket, ttl_s)
    default_dir = Path(tempfile.gettempdir()) / "sastcore_reports"
    directory = Path(os.environ.get("SASTCORE_REPORTS_DIR", default_dir))
    return FilesystemReportStore(directory, ttl_s)
