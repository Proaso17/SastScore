"""Compilación de patrones a AST.

Un patrón es un fragmento de código con metavariables (``$X``) y elipsis (``...``).
Como ``$`` no es válido en Python y ``...`` no lo es suelto en JS, se **preprocesa**
el patrón sustituyendo esas marcas por identificadores sentinela válidos en cualquier
lenguaje, y luego se parsea con la **misma gramática** que el código objetivo
(ADR-0001). El matcher reconoce después esos sentinelas.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sastcore.discovery.languages import Language
from sastcore.parsing.ast import Node, parse

MV_PREFIX = "SASTCORE_MV_"
ELLIPSIS_SENTINEL = "SASTCORE_ELLIPSIS"

_METAVAR_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")
_ELLIPSIS_RE = re.compile(r"\.\.\.")

_WRAPPER_TYPES = frozenset({"module", "program", "expression_statement"})


class PatternError(ValueError):
    """El patrón no se pudo parsear en el lenguaje indicado."""


def _preprocess(pattern: str) -> str:
    processed = _METAVAR_RE.sub(lambda m: MV_PREFIX + m.group(1), pattern)
    return _ELLIPSIS_RE.sub(ELLIPSIS_SENTINEL, processed)


def _unwrap(node: Node) -> Node:
    """Descarta envoltorios (module/program/expression_statement) de un solo hijo."""
    current = node
    while current.type in _WRAPPER_TYPES:
        named = current.named_children
        if len(named) != 1:
            break
        current = named[0]
    return current


@dataclass(frozen=True)
class CompiledPattern:
    """Un patrón ya parseado y desenvuelto, listo para el matcher."""

    language: Language
    root: Node
    source: str


def compile_pattern(language: Language, pattern: str) -> CompiledPattern:
    """Compila ``pattern`` para ``language``; lanza :class:`PatternError` si no parsea."""
    root = parse(language, _preprocess(pattern))
    if root.has_error:
        raise PatternError(f"patrón no parseable para {language.value}: {pattern!r}")
    return CompiledPattern(language=language, root=_unwrap(root), source=pattern)
