"""Cache de parseo por run (ADR-0004).

Nivel 1 (implementado aquí): cada contenido se parsea una sola vez por ejecución y
el AST se comparte entre pasadas. Nivel 2 (cache persistente cross-run en
``.sastcore-cache/``, clave = hash de contenido + versión + hash de reglas) se
implementará en la Fase 5, junto al baseline.
"""

from __future__ import annotations

import hashlib

from sastcore.discovery.languages import Language
from sastcore.parsing.ast import Node, parse


class ParseCache:
    """Memoiza el parseo por (lenguaje, hash de contenido) dentro de un run."""

    def __init__(self) -> None:
        self._cache: dict[str, Node] = {}

    def get(self, language: Language, source: str) -> Node:
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        key = f"{language.value}:{digest}"
        cached = self._cache.get(key)
        if cached is None:
            cached = parse(language, source)
            self._cache[key] = cached
        return cached
