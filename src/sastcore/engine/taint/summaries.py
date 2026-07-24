"""Resúmenes de función intra-fichero: ``param N tainted → retorno tainted``.

Se calculan tratando cada parámetro como semilla tainted y viendo si el taint llega a
un ``return``. Se itera a fixpoint para que las llamadas entre funciones del mismo
fichero se propaguen. Sin sanitizers (sobre-aproximación conservadora, sesgo a recall).
"""

from __future__ import annotations

from collections.abc import Sequence

from sastcore.engine.taint.adapters import LangSpec
from sastcore.engine.taint.propagation import Engine
from sastcore.engine.taint.state import TaintState
from sastcore.parsing.ast import Node

_MAX_ITERS = 5


def compute_summaries(
    functions: Sequence[tuple[str, Node]],
    *,
    spec: LangSpec,
    rel_path: str,
    file_lines: Sequence[str],
) -> dict[str, frozenset[int]]:
    """Devuelve, por nombre de función, el conjunto de índices de parámetro que taintean
    el valor de retorno."""
    summaries: dict[str, frozenset[int]] = {}

    for _ in range(_MAX_ITERS):
        changed = False
        for name, func in functions:
            body = func.child_by_field_name(spec.body_field)
            if body is None:
                continue
            params = spec.function_params(func)
            tainting: set[int] = set()
            for index, param in enumerate(params):
                engine = Engine(
                    spec=spec,
                    rel_path=rel_path,
                    file_lines=file_lines,
                    summaries=summaries,
                    track_trace=False,
                )
                result = engine.run(body, TaintState({param: ()}))
                if result.return_tainted:
                    tainting.add(index)
            new = frozenset(tainting)
            if summaries.get(name) != new:
                summaries[name] = new
                changed = True
        if not changed:
            break

    return summaries
