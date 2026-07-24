"""Estado de taint: conjunto de ubicaciones tainted con su traza de origen.

Se trata como inmutable: cada operación devuelve un ``TaintState`` nuevo. La traza
(``witness``) es la secuencia de :class:`DataFlowStep` que explica por qué una ubicación
está tainted (source → … → aquí), y alimenta el ``data_flow`` del hallazgo.
"""

from __future__ import annotations

from collections.abc import Iterable

from sastcore.findings.model import DataFlowStep

Witness = tuple[DataFlowStep, ...]


class TaintState:
    """Ubicaciones tainted (por nombre canónico) → traza de cómo llegaron a estarlo."""

    __slots__ = ("_map",)

    def __init__(self, mapping: dict[str, Witness] | None = None) -> None:
        self._map: dict[str, Witness] = dict(mapping) if mapping else {}

    def is_tainted(self, location: str) -> bool:
        return location in self._map

    def witness(self, location: str) -> Witness:
        return self._map.get(location, ())

    def with_tainted(self, location: str, witness: Witness) -> TaintState:
        new = dict(self._map)
        new[location] = witness
        return TaintState(new)

    def without(self, location: str) -> TaintState:
        if location not in self._map:
            return self
        new = dict(self._map)
        del new[location]
        return TaintState(new)

    def union(self, other: TaintState) -> TaintState:
        """Une dos estados (semántica path-insensitive en los joins de control)."""
        new = dict(self._map)
        for location, witness in other._map.items():
            if location not in new:
                new[location] = witness
        return TaintState(new)

    def locations(self) -> frozenset[str]:
        return frozenset(self._map)

    @classmethod
    def from_locations(cls, locations: Iterable[str], witness: Witness = ()) -> TaintState:
        return cls(dict.fromkeys(locations, witness))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TaintState) and self.locations() == other.locations()

    def __hash__(self) -> int:
        return hash(self.locations())
