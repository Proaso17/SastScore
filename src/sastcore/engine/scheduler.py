"""Orquestador del escaneo.

Fase 1: recorre los ficheros (discovery) y les aplica la pasada de secretos, agrega
y deduplica. Sin paralelismo todavía (se medirá antes de introducir procesos: el
parseo pesado llega en la Fase 2).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from sastcore.discovery.walker import FileWalker
from sastcore.engine.secrets.pass_ import SecretsPass
from sastcore.findings.dedup import deduplicate
from sastcore.findings.model import Finding

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Resultado agregado de un escaneo."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0


class Scheduler:
    """Coordina discovery y las pasadas de análisis sobre ficheros o directorios."""

    def __init__(self, *, secrets_pass: SecretsPass | None = None) -> None:
        self._secrets = secrets_pass if secrets_pass is not None else SecretsPass()

    def run(self, root: Path, *, walker: FileWalker | None = None) -> ScanResult:
        """Escanea el directorio ``root`` y devuelve los hallazgos deduplicados."""
        walker = walker if walker is not None else FileWalker(root)
        findings: list[Finding] = []
        files_scanned = 0
        for path in walker.walk():
            rel_path = path.relative_to(root).as_posix()
            findings.extend(self._scan_one(path, rel_path))
            files_scanned += 1
        return ScanResult(findings=deduplicate(findings), files_scanned=files_scanned)

    def run_file(self, path: Path, *, rel_path: str | None = None) -> ScanResult:
        """Escanea un único fichero."""
        rel = rel_path if rel_path is not None else path.name
        findings = deduplicate(self._scan_one(path, rel))
        return ScanResult(findings=findings, files_scanned=1)

    def _scan_one(self, path: Path, rel_path: str) -> list[Finding]:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:  # pragma: no cover - E/S puntual
            logger.debug("No se pudo leer %s: %s", path, exc)
            return []
        return self._secrets.scan_file(rel_path=rel_path, content=content)
