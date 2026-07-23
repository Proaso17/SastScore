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


def _match(pat: Node, tgt: Node, binds: _Bindings) -> _Bindings | None:
    name = _metavar_name(pat)
    if name is not None:
        existing = binds.get(name)
        if existing is not None:
            return binds if existing == tgt.text else None
        return {**binds, name: tgt.text}

    if pat.type != tgt.type:
        return None

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


def find_matches(pattern: CompiledPattern, tree: Node) -> list[Match]:
    """Encuentra todos los matches de ``pattern`` en ``tree``."""
    core = pattern.root
    root_is_metavar = _metavar_name(core) is not None
    matches: list[Match] = []
    for node in tree.walk_preorder():
        if not root_is_metavar and node.type != core.type:
            continue
        bindings = _match(core, node, {})
        if bindings is not None:
            matches.append(Match(node=node, bindings=bindings))
    return matches
