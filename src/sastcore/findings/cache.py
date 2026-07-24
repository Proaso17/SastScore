"""Cache persistente de hallazgos por hash de contenido (ADR-0004).

Acelera los re-escaneos incrementales: si un fichero no cambió y ni la versión de la
herramienta ni los rulepacks cambiaron, se reutilizan los hallazgos cacheados (con el
``path`` re-estampado, ya que el fingerprint es independiente del path).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

from sastcore import __version__
from sastcore.findings.model import Finding

_CACHE_DIRNAME = ".sastcore-cache"
_SCHEMA_VERSION = "1"


def content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def rulepacks_hash(rulepacks_dir: Path) -> str:
    """Hash del contenido de todos los rulepacks, para invalidar la cache si cambian."""
    digest = hashlib.sha256()
    for yml in sorted(rulepacks_dir.rglob("*.yml")):
        digest.update(yml.read_bytes())
    return digest.hexdigest()


def config_hash(rulepacks_dir: Path) -> str:
    """Identidad de la configuración: versión de la herramienta + hash de reglas."""
    return hashlib.sha256(f"{__version__}:{rulepacks_hash(rulepacks_dir)}".encode()).hexdigest()


def _restamp(finding: Finding, rel_path: str) -> Finding:
    location = replace(finding.location, path=rel_path)
    data_flow = [
        replace(step, location=replace(step.location, path=rel_path)) for step in finding.data_flow
    ]
    return finding.model_copy(update={"location": location, "data_flow": data_flow})


class FindingsCache:
    """Cache en disco de los hallazgos por fichero."""

    def __init__(self, root: Path, *, config: str) -> None:
        self._dir = root / _CACHE_DIRNAME / "findings"
        self._config = config

    def get(self, digest: str, rel_path: str) -> list[Finding] | None:
        path = self._dir / f"{digest}.json"
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if data.get("schema") != _SCHEMA_VERSION or data.get("config") != self._config:
            return None
        findings = [Finding.model_validate(item) for item in data.get("findings", [])]
        return [_restamp(finding, rel_path) for finding in findings]

    def put(self, digest: str, findings: list[Finding]) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": _SCHEMA_VERSION,
            "config": self._config,
            "findings": [finding.model_dump(mode="json") for finding in findings],
        }
        (self._dir / f"{digest}.json").write_text(json.dumps(payload), encoding="utf-8")
