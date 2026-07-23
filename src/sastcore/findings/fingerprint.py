"""Fingerprint de hallazgos, estilo ``partialFingerprints`` de SARIF (ADR-0002).

La identidad de un hallazgo se calcula a partir de:

- el ``rule_id``,
- un **contexto rodante normalizado** (±``window`` líneas alrededor del match, con
  los espacios colapsados), que la hace estable si el bloque se mueve de línea, y
- un **índice de ocurrencia** que desambigua repeticiones del mismo contexto dentro
  de un fichero.

El ``path`` **no** entra en el fingerprint (así sobrevive a renombrados de fichero).
La deduplicación dentro de un mismo escaneo sí usa el ``path`` como desempate para no
colapsar dos hallazgos reales con el mismo snippet en ficheros distintos
(ver :mod:`sastcore.findings.dedup`).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence

_WHITESPACE = re.compile(r"\s+")
_NUL = "\x00"


def _normalize(line: str) -> str:
    """Colapsa espacios y recorta, para que el formato no afecte al fingerprint."""
    return _WHITESPACE.sub(" ", line).strip()


def rolling_context(file_lines: Sequence[str], match_line: int, window: int) -> str:
    """Devuelve el contexto normalizado alrededor de ``match_line`` (1-indexado)."""
    idx = match_line - 1
    start = max(0, idx - window)
    end = min(len(file_lines), idx + window + 1)
    return "\n".join(_normalize(file_lines[i]) for i in range(start, end))


def compute_fingerprint(
    *,
    rule_id: str,
    file_lines: Sequence[str],
    match_line: int,
    occurrence_index: int = 0,
    window: int = 3,
) -> str:
    """Calcula el fingerprint sha256 (hex) de un hallazgo.

    Args:
        rule_id: identificador de la regla.
        file_lines: líneas del fichero (sin el salto de línea final).
        match_line: línea del match, 1-indexada.
        occurrence_index: índice de ocurrencia del mismo contexto en el fichero.
        window: nº de líneas de contexto a cada lado.
    """
    context = rolling_context(file_lines, match_line, window)
    payload = f"{rule_id}{_NUL}{context}{_NUL}{occurrence_index}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
