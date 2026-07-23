"""Orquestador del escaneo.

Por fichero: pasada de secretos (sobre el texto) + pasada de patrones (sobre el AST,
parseado una sola vez por run vía :class:`ParseCache`), luego se aplica la supresión
inline y se acumula. Al final se deduplica. Sin paralelismo todavía (se medirá antes
de introducir procesos).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from sastcore.discovery.languages import detect_language
from sastcore.discovery.walker import FileWalker
from sastcore.engine.pattern.pass_ import PatternPass
from sastcore.engine.secrets.pass_ import SecretsPass
from sastcore.findings.dedup import deduplicate
from sastcore.findings.model import Finding
from sastcore.parsing.cache import ParseCache
from sastcore.suppression import apply_suppressions

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Resultado agregado de un escaneo."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0


class Scheduler:
    """Coordina discovery y las pasadas de análisis sobre ficheros o directorios."""

    def __init__(
        self,
        *,
        secrets_pass: SecretsPass | None = None,
        pattern_pass: PatternPass | None = None,
    ) -> None:
        self._secrets = secrets_pass if secrets_pass is not None else SecretsPass()
        self._pattern = pattern_pass
        self._parse_cache = ParseCache()

    def run(self, root: Path, *, walker: FileWalker | None = None) -> ScanResult:
        """Escanea el directorio ``root`` y devuelve los hallazgos deduplicados."""
        walker = walker if walker is not None else FileWalker(root)
        findings: list[Finding] = []
        files_scanned = 0
        for path, rel_path in walker.walk():
            findings.extend(self._scan_one(path, rel_path))
            files_scanned += 1
        return ScanResult(findings=deduplicate(findings), files_scanned=files_scanned)

    def run_file(self, path: Path, *, rel_path: str | None = None) -> ScanResult:
        """Escanea un único fichero."""
        rel = rel_path if rel_path is not None else path.name
        return ScanResult(findings=deduplicate(self._scan_one(path, rel)), files_scanned=1)

    def _scan_one(self, path: Path, rel_path: str) -> list[Finding]:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:  # pragma: no cover - E/S puntual
            logger.debug("No se pudo leer %s: %s", path, exc)
            return []

        lines = content.splitlines()
        findings = self._secrets.scan_file(rel_path=rel_path, content=content)

        if self._pattern is not None:
            language = detect_language(path, lines[0] if lines else None)
            if language is not None:
                try:
                    tree = self._parse_cache.get(language, content)
                    findings.extend(
                        self._pattern.scan(
                            rel_path=rel_path,
                            tree=tree,
                            file_lines=lines,
                            language=language,
                        )
                    )
                except Exception as exc:  # pragma: no cover - robustez ante parseo
                    logger.debug("Fallo al analizar %s: %s", path, exc)

        return apply_suppressions(findings, lines)
