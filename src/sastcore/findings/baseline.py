"""Baseline: snapshot de fingerprints para el modo diferencial de CI.

Como el fingerprint es independiente del path (ADR-0002), el baseline sobrevive a que el
código se mueva de línea o el fichero se renombre: solo se reportan hallazgos **nuevos**.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from sastcore import __version__
from sastcore.findings.model import Finding


@dataclass(frozen=True)
class Baseline:
    """Conjunto de fingerprints de un escaneo previo."""

    fingerprints: frozenset[str]

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> Baseline:
        return cls(frozenset(finding.fingerprint for finding in findings))

    @classmethod
    def load(cls, path: Path) -> Baseline:
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(frozenset(data.get("fingerprints", [])))

    def save(self, path: Path) -> None:
        payload = {
            "tool": "sastcore",
            "version": __version__,
            "fingerprints": sorted(self.fingerprints),
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def filter_new(findings: list[Finding], baseline: Baseline) -> list[Finding]:
    """Devuelve solo los hallazgos que no estaban en el baseline."""
    return [f for f in findings if f.fingerprint not in baseline.fingerprints]
