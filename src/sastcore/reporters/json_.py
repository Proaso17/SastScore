"""Reporter JSON: salida estable y determinista para consumo por máquina."""

from __future__ import annotations

import json

from sastcore import __version__
from sastcore.findings.model import Finding


class JSONReporter:
    """Serializa los hallazgos a JSON indentado."""

    def render(self, findings: list[Finding], *, files_scanned: int) -> str:
        payload = {
            "tool": "sastcore",
            "version": __version__,
            "files_scanned": files_scanned,
            "findings": [finding.model_dump(mode="json") for finding in findings],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)
