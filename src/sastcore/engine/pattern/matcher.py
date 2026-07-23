"""Matching estructural CST↔CST con metavariables y elipsis.

El algoritmo compara la estructura de nodos *named* (ignorando así formato y
comentarios). Una metavariable casa cualquier subárbol, con consistencia (la misma
``$X`` debe casar el mismo texto). La elipsis casa cero o más elementos en listas de
hijos (argumentos, sentencias).

Limitación conocida (MVP): no se distinguen operadores dentro de una expresión
(``a + b`` y ``a - b`` casan igual), ni se soporta elipsis en posiciones arbitrarias.
"""

from __future__ import annotations

from dataclasses import dataclass

from sastcore.engine.pattern.compile import ELLIPSIS_SENTINEL, MV_PREFIX, CompiledPattern
from sastcore.parsing.ast import Node

_Bindings = dict[str, str]


@dataclass
class Match:
    """Un match de un patrón en el árbol objetivo."""

    node: Node
    bindings: _Bindings


def _metavar_name(node: Node) -> str | None:
    if not node.named_children and node.text.startswith(MV_PREFIX):
        return node.text[len(MV_PREFIX) :]
    return None


def _is_ellipsis(node: Node) -> bool:
    return not node.named_children and node.text == ELLIPSIS_SENTINEL


_QUOTES = "\"'`"


def _string_content(node: Node) -> str:
    """Contenido de un literal string sin las comillas (para comparar sin importar estilo)."""
    text = node.text
    if len(text) >= 2 and text[0] in _QUOTES and text[-1] == text[0]:
        return text[1:-1]
    return text


def _match(pat: Node, tgt: Node, binds: _Bindings) -> _Bindings | None:
    name = _metavar_name(pat)
    if name is not None:
        existing = binds.get(name)
        if existing is not None:
            return binds if existing == tgt.text else None
        return {**binds, name: tgt.text}

    if pat.type != tgt.type:
        return None

    # Los literales string se comparan por contenido, ignorando el estilo de comillas
    # (coherente con "ignorar formato"): "md5" y 'md5' casan igual.
    if pat.type == "string":
        return binds if _string_content(pat) == _string_content(tgt) else None

    pat_named = pat.named_children
    tgt_named = tgt.named_children
    if not pat_named and not tgt_named:
        return binds if pat.text == tgt.text else None
    return _match_list(pat_named, tgt_named, binds)


def _match_list(pats: list[Node], tgts: list[Node], binds: _Bindings) -> _Bindings | None:
    if not pats:
        return binds if not tgts else None

    if _is_ellipsis(pats[0]):
        for consumed in range(len(tgts) + 1):
            result = _match_list(pats[1:], tgts[consumed:], binds)
            if result is not None:
                return result
        return None

    if not tgts:
        return None
    head = _match(pats[0], tgts[0], binds)
    if head is None:
        return None
    return _match_list(pats[1:], tgts[1:], head)


def root_is_metavar(pattern: CompiledPattern) -> bool:
    """Indica si el nodo raíz del patrón es una metavariable (casa cualquier nodo)."""
    return _metavar_name(pattern.root) is not None


def match_node(pattern: CompiledPattern, node: Node) -> _Bindings | None:
    """Intenta casar ``pattern`` en ``node`` concreto; devuelve las bindings o ``None``."""
    return _match(pattern.root, node, {})


def find_matches(pattern: CompiledPattern, tree: Node) -> list[Match]:
    """Encuentra todos los matches de ``pattern`` en ``tree`` (recorrido propio)."""
    is_metavar = root_is_metavar(pattern)
    core_type = pattern.root.type
    matches: list[Match] = []
    for node in tree.walk_preorder():
        if not is_metavar and node.type != core_type:
            continue
        bindings = match_node(pattern, node)
        if bindings is not None:
            matches.append(Match(node=node, bindings=bindings))
    return matches
