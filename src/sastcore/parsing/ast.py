"""Wrapper fino y estable sobre los nodos de tree-sitter (ADR-0001).

Aísla al resto del código de la API concreta del parser. Expone solo lo que los
motores necesitan: tipo, texto, posición e hijos (con distinción named/anónimo).
"""

from __future__ import annotations

from collections.abc import Iterator

from tree_sitter import Node as TSNode

from sastcore.discovery.languages import Language
from sastcore.parsing.loader import get_parser


class Node:
    """Nodo del AST. Las posiciones son ``(fila, columna)`` 0-indexadas."""

    __slots__ = ("_node",)

    def __init__(self, node: TSNode) -> None:
        self._node = node

    @property
    def type(self) -> str:
        return self._node.type

    @property
    def text(self) -> str:
        raw = self._node.text
        return raw.decode("utf-8", "replace") if raw is not None else ""

    @property
    def is_named(self) -> bool:
        return self._node.is_named

    @property
    def has_error(self) -> bool:
        return self._node.has_error

    @property
    def start_point(self) -> tuple[int, int]:
        point = self._node.start_point
        return (point.row, point.column)

    @property
    def end_point(self) -> tuple[int, int]:
        point = self._node.end_point
        return (point.row, point.column)

    @property
    def children(self) -> list[Node]:
        return [Node(child) for child in self._node.children]

    @property
    def named_children(self) -> list[Node]:
        return [Node(child) for child in self._node.named_children]

    def child_by_field_name(self, name: str) -> Node | None:
        child = self._node.child_by_field_name(name)
        return Node(child) if child is not None else None

    def walk_preorder(self) -> Iterator[Node]:
        """Recorre el subárbol en preorden (incluye este nodo)."""
        yield self
        for child in self.children:
            yield from child.walk_preorder()

    def __repr__(self) -> str:  # pragma: no cover - ayuda de depuración
        return f"Node({self.type!r}, {self.text!r:.40})"


def parse(language: Language, source: str) -> Node:
    """Parsea ``source`` con la gramática de ``language`` y devuelve la raíz."""
    parser = get_parser(language)
    tree = parser.parse(source.encode("utf-8"))
    return Node(tree.root_node)
