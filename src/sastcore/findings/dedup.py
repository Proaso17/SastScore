"""Deduplicación de hallazgos.

Colapsa hallazgos que representan la misma ocurrencia física. La clave incluye el
``path`` además del ``fingerprint`` para no fusionar dos hallazgos reales que
comparten snippet en ficheros distintos (ver ADR-0002). El resultado es
determinista: ordenado por ``Finding.sort_key()``.
"""

from __future__ import annotations

from collections.abc import Iterable

from sastcore.findings.model import Finding


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    """Elimina duplicados exactos y devuelve la lista ordenada de forma estable."""
    seen: set[tuple[str, str]] = set()
    result: list[Finding] = []
    for finding in sorted(findings, key=Finding.sort_key):
        key = (finding.location.path, finding.fingerprint)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result
