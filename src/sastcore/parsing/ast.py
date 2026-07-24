"""Wrapper de AST estable (ADR-0001).

El árbol de tree-sitter se **materializa** a objetos Python puros en el momento del
parseo y el ``Tree`` se descarta. Los nodos de tree-sitter son punteros perezosos al
árbol/fuente y provocan use-after-free (segfault) si se acceden tras liberarse; al
copiar todo lo necesario (tipo, texto, posición, hijos, campos) el resto del motor
opera sobre datos inmutables sin tocar C ni depender de ciclos de vida.
"""

from __future__ import annotations

import gc
from collections.abc import Iterator
from dataclasses import dataclass

from tree_sitter import Node as TSNode

from sastcore.discovery.languages import Language
from sastcore.parsing.loader import get_parser


@dataclass(slots=True, eq=False)
class Node:
    """Nodo del AST materializado. Posiciones ``(fila, columna)`` 0-indexadas."""

    type: str
    text: str
    is_named: bool
    has_error: bool
    start_point: tuple[int, int]
    end_point: tuple[int, int]
    _children: tuple[Node, ...]
    _fields: dict[str, Node]

    @property
    def children(self) -> list[Node]:
        return list(self._children)

    @property
    def named_children(self) -> list[Node]:
        return [child for child in self._children if child.is_named]

    def child_by_field_name(self, name: str) -> Node | None:
        return self._fields.get(name)

    def walk_preorder(self) -> Iterator[Node]:
        """Recorre el subárbol en preorden (incluye este nodo)."""
        stack: list[Node] = [self]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(node._children))

    def __repr__(self) -> str:  # pragma: no cover - ayuda de depuración
        return f"Node({self.type!r}, {self.text!r:.30})"


# Datos crudos de un nodo (fase 1). Es una **tupla de primitivos** a propósito: las
# tuplas que solo contienen objetos atómicos no las rastrea el GC cíclico, así que no
# disparan una recolección en medio de la travesía (donde el binding de tree-sitter
# crashea al escanear sus nodos).
_Record = tuple[str, str, bool, bool, tuple[int, int], tuple[int, int], str | None]


def _collect(root: TSNode) -> tuple[list[_Record], list[int]]:
    """Recorrido iterativo en preorden vía ``node.children`` (no cursor).

    Los nodos de tree-sitter obtenidos con el cursor forman ciclos que, acumulados entre
    parseos, hacen crashear al GC cíclico al recolectarlos; los de ``.children`` se liberan
    por refcount (se retienen en la pila mientras se recorren). Los registros son tuplas de
    primitivos (no rastreadas por el GC) para no disparar recolecciones en medio.
    """
    records: list[_Record] = []
    parents: list[int] = []
    node_stack: list[TSNode] = [root]
    parent_stack: list[int] = [-1]
    field_stack: list[str | None] = [None]
    while node_stack:
        node = node_stack.pop()
        parent = parent_stack.pop()
        field_name = field_stack.pop()
        raw = node.text
        start = node.start_point
        end = node.end_point
        index = len(records)
        records.append(
            (
                node.type,
                raw.decode("utf-8", "replace") if raw is not None else "",
                node.is_named,
                node.has_error,
                (start.row, start.column),
                (end.row, end.column),
                field_name,
            )
        )
        parents.append(parent)

        children = node.children
        for i in range(len(children) - 1, -1, -1):
            node_stack.append(children[i])
            parent_stack.append(index)
            field_stack.append(node.field_name_for_child(i))
    return records, parents


def _build(records: list[_Record], parents: list[int]) -> Node:
    """Construye los :class:`Node` inmutables bottom-up (los hijos van antes que el padre)."""
    count = len(records)
    child_indices: list[list[int]] = [[] for _ in range(count)]
    for index in range(1, count):
        child_indices[parents[index]].append(index)

    built: list[Node] = [_PLACEHOLDER] * count
    for index in range(count - 1, -1, -1):
        record = records[index]
        indices = child_indices[index]
        children = tuple(built[c] for c in indices)
        fields = {records[c][6]: built[c] for c in indices if records[c][6] is not None}
        built[index] = Node(
            type=record[0],
            text=record[1],
            is_named=record[2],
            has_error=record[3],
            start_point=record[4],
            end_point=record[5],
            _children=children,
            _fields=fields,  # type: ignore[arg-type]  # keys son str (filtrados no None)
        )
    return built[0]


_PLACEHOLDER = Node(
    type="",
    text="",
    is_named=False,
    has_error=False,
    start_point=(0, 0),
    end_point=(0, 0),
    _children=(),
    _fields={},
)


def parse(language: Language, source: str) -> Node:
    """Parsea ``source`` con la gramática de ``language`` y devuelve la raíz materializada.

    El árbol se materializa a :class:`Node` inmutables (fase de recolección iterativa +
    construcción bottom-up) y el árbol de tree-sitter se descarta. Así el resto del motor
    opera sobre datos puros de Python, sin depender del frágil ciclo de vida de los nodos
    perezosos de tree-sitter (que provocan segfaults al liberarse o al recolectarse).
    """
    # El binding de tree-sitter de esta plataforma crashea si el **GC cíclico** escanea o
    # recolecta sus objetos (Tree/Node forman ciclos irrompibles). Se desactiva el GC de
    # forma permanente al parsear; los objetos de tree-sitter (acotados por fichero) se
    # abandonan y el SO recupera la memoria al salir (ver docs/adr y os._exit en el CLI).
    gc.disable()
    parser = get_parser(language)
    source_bytes = source.encode("utf-8")
    tree = parser.parse(source_bytes)
    records, parents = _collect(tree.root_node)
    return _build(records, parents)
