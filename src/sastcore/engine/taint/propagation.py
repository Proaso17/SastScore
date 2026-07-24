"""Motor de propagación de taint (interpretación abstracta dirigida por sintaxis).

Recorre el cuerpo de una función hilando un :class:`TaintState`: la secuencia lo
encadena, el ``if`` une las ramas (path-insensitive → un sanitizer solo limpia si domina
el sink), los bucles iteran a fixpoint. Reutiliza el matcher de patrones de la Fase 2
para reconocer sources/sanitizers/sinks. Produce hallazgos con su traza ``data_flow``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from sastcore.engine.pattern.compile import CompiledPattern
from sastcore.engine.pattern.matcher import match_node
from sastcore.engine.taint.adapters import LangSpec
from sastcore.engine.taint.state import TaintState, Witness
from sastcore.findings.model import DataFlowStep, Location
from sastcore.parsing.ast import Node

_MAX_LOOP_ITERS = 8

_DUMMY_STEP = DataFlowStep(
    location=Location(path="", start_line=1, start_col=0, end_line=1, end_col=0), message=""
)


@dataclass
class SinkSpec:
    """Un sink compilado con el índice del argumento a vigilar y su regla."""

    pattern: CompiledPattern
    taint_arg: int
    rule_id: str


@dataclass
class TaintFinding:
    """Un flujo source → sink detectado."""

    rule_id: str
    sink_node: Node
    data_flow: list[DataFlowStep]


@dataclass
class RunResult:
    final_state: TaintState
    findings: list[TaintFinding] = field(default_factory=list)
    return_tainted: bool = False


class Engine:
    """Análisis de taint de un ámbito (función o módulo) para un conjunto de patrones."""

    def __init__(
        self,
        *,
        spec: LangSpec,
        rel_path: str,
        file_lines: Sequence[str],
        sources: Sequence[CompiledPattern] = (),
        sanitizers: Sequence[CompiledPattern] = (),
        sinks: Sequence[SinkSpec] = (),
        summaries: dict[str, frozenset[int]] | None = None,
        track_trace: bool = True,
    ) -> None:
        self.spec = spec
        self.rel_path = rel_path
        self.file_lines = file_lines
        self.sources = list(sources)
        self.sanitizers = list(sanitizers)
        self.sinks = list(sinks)
        self.summaries = summaries or {}
        # Los resúmenes no necesitan la traza; evitar crear millones de objetos pydantic
        # (Location/DataFlowStep) es una gran optimización y evita el coste de liberarlos.
        self._track_trace = track_trace
        self._findings: list[TaintFinding] = []
        self._return_tainted = False
        self._seen: set[tuple[str, int, int]] = set()

    # -- API -----------------------------------------------------------------
    def run(self, body: Node, initial: TaintState) -> RunResult:
        self._findings = []
        self._return_tainted = False
        self._seen = set()
        final = self._analyze_block(body, initial)
        return RunResult(final, self._findings, self._return_tainted)

    # -- construcción de pasos -----------------------------------------------
    def _location(self, node: Node) -> Location:
        sr, sc = node.start_point
        er, ec = node.end_point
        return Location(
            path=self.rel_path, start_line=sr + 1, start_col=sc, end_line=er + 1, end_col=ec
        )

    def _step(self, node: Node, message: str) -> DataFlowStep:
        if not self._track_trace:
            return _DUMMY_STEP
        return DataFlowStep(location=self._location(node), message=message)

    # -- reconocimiento de patrones ------------------------------------------
    def _matches_any(self, patterns: Sequence[CompiledPattern], node: Node) -> bool:
        return any(match_node(p, node) is not None for p in patterns)

    def _canonical(self, node: Node) -> str | None:
        node = self.spec.unwrap_paren(node)
        if node.type == self.spec.name_type:
            return node.text
        if node.type == self.spec.member_type:
            return node.text
        return None

    # -- taint de una expresión ----------------------------------------------
    def is_tainted(self, node: Node, state: TaintState) -> Witness | None:
        node = self.spec.unwrap_paren(node)

        if self._matches_any(self.sanitizers, node):
            return None
        if self._matches_any(self.sources, node):
            return (self._step(node, "entrada no confiable (source)"),)

        t = node.type
        if t == self.spec.name_type:
            loc = node.text
            return state.witness(loc) if state.is_tainted(loc) else None

        if t == self.spec.member_type:
            obj = node.child_by_field_name(self.spec.member_object_field)
            if obj is not None:
                witness = self.is_tainted(obj, state)
                if witness is not None:
                    return witness
            loc = node.text
            return state.witness(loc) if state.is_tainted(loc) else None

        if t == self.spec.subscript_type:
            obj = node.child_by_field_name(self.spec.subscript_object_field)
            return self.is_tainted(obj, state) if obj is not None else None

        if t in self.spec.binary_types:
            return self._any_child_tainted(node.named_children, state)

        if t in self.spec.string_types:
            return self._interpolation_tainted(node, state)

        if t == self.spec.call_type:
            return self._call_tainted(node, state)

        return None

    def _any_child_tainted(self, nodes: Sequence[Node], state: TaintState) -> Witness | None:
        for child in nodes:
            witness = self.is_tainted(child, state)
            if witness is not None:
                return witness
        return None

    def _interpolation_tainted(self, node: Node, state: TaintState) -> Witness | None:
        for descendant in node.walk_preorder():
            if descendant.type in self.spec.interpolation_types:
                witness = self._any_child_tainted(descendant.named_children, state)
                if witness is not None:
                    return witness
        return None

    def _call_tainted(self, node: Node, state: TaintState) -> Witness | None:
        func = node.child_by_field_name(self.spec.call_func_field)
        if func is None:
            return None
        # Llamada a método sobre un receptor tainted: propaga (p. ej. x.strip()).
        if func.type == self.spec.member_type:
            recv = func.child_by_field_name(self.spec.member_object_field)
            if recv is not None:
                witness = self.is_tainted(recv, state)
                if witness is not None:
                    return witness
        # Resumen de función local: si algún argumento que taintea el retorno lo está.
        name = func.text if func.type == self.spec.name_type else None
        if name is not None and name in self.summaries:
            args = self._call_args(node)
            for index in self.summaries[name]:
                if index < len(args):
                    witness = self.is_tainted(args[index], state)
                    if witness is not None:
                        return witness
        return None

    def _call_args(self, call: Node) -> list[Node]:
        arguments = call.child_by_field_name(self.spec.call_args_field)
        return arguments.named_children if arguments is not None else []

    # -- comprobación de sinks -----------------------------------------------
    def _check_sinks(self, expr: Node | None, state: TaintState) -> None:
        if expr is None or not self.sinks:
            return
        for descendant in expr.walk_preorder():
            if descendant.type != self.spec.call_type:
                continue
            for sink in self.sinks:
                if match_node(sink.pattern, descendant) is None:
                    continue
                args = self._call_args(descendant)
                if sink.taint_arg >= len(args):
                    continue
                witness = self.is_tainted(args[sink.taint_arg], state)
                if witness is not None:
                    row, col = descendant.start_point
                    key = (sink.rule_id, row, col)
                    if key in self._seen:
                        continue
                    self._seen.add(key)
                    trace = [*witness, self._step(descendant, "llega a un sink peligroso")]
                    self._findings.append(TaintFinding(sink.rule_id, descendant, trace))

    # -- análisis de sentencias ----------------------------------------------
    def _analyze_block(self, block: Node, state: TaintState) -> TaintState:
        for stmt in block.named_children:
            state = self._analyze_stmt(stmt, state)
        return state

    def _analyze_stmt(self, node: Node, state: TaintState) -> TaintState:
        spec = self.spec
        t = node.type

        if t in spec.function_types:
            return state  # ámbito aparte; se analiza por separado
        if t in spec.block_types:
            return self._analyze_block(node, state)
        if t == spec.if_type:
            return self._analyze_if(node, state)
        if t == spec.while_type or t in spec.for_types:
            return self._analyze_loop(node, state)
        if t == spec.try_type:
            return self._analyze_try(node, state)
        if t == spec.return_type:
            return self._analyze_return(node, state)
        if t == spec.expr_stmt_type:
            inner = node.named_children[0] if node.named_children else None
            self._check_sinks(inner, state)
            if inner is not None and inner.type in spec.assign_types:
                return self._apply_assignment(inner, state)
            if inner is not None and inner.type == spec.call_type:
                return self._container_mutation(inner, state)
            return state
        if t == spec.call_type:  # llamada suelta como sentencia (p. ej. en Python)
            self._check_sinks(node, state)
            return self._container_mutation(node, state)
        if t in spec.var_decl_types:
            return self._apply_var_decl(node, state)
        if t in spec.assign_types:
            right = node.child_by_field_name(spec.assign_right_field)
            self._check_sinks(right, state)
            return self._apply_assignment(node, state)

        # Otra sentencia: solo comprobamos sinks embebidos.
        self._check_sinks(node, state)
        return state

    def _container_mutation(self, call: Node, state: TaintState) -> TaintState:
        """`c.push(x)` / `c.append(x)` con x tainted → marca el contenedor c tainted."""
        func = call.child_by_field_name(self.spec.call_func_field)
        if func is None or func.type != self.spec.member_type:
            return state
        method = func.child_by_field_name(self.spec.member_prop_field)
        if method is None or method.text not in self.spec.container_methods:
            return state
        recv = func.child_by_field_name(self.spec.member_object_field)
        base = self._canonical(recv) if recv is not None else None
        if base is None or recv is None:
            return state
        for arg in self._call_args(call):
            witness = self.is_tainted(arg, state)
            if witness is not None:
                trace = (*witness, self._step(recv, "elemento tainted añadido al contenedor"))
                return state.with_tainted(base, trace)
        return state

    def _analyze_if(self, node: Node, state: TaintState) -> TaintState:
        condition = node.child_by_field_name("condition")
        self._check_sinks(condition, state)

        consequence = node.child_by_field_name("consequence")
        s1 = self._analyze_stmt_or_block(consequence, state) if consequence else state

        alternative = node.child_by_field_name("alternative")
        if alternative is None:
            # Sin else: la rama no tomada preserva el estado de entrada.
            return s1.union(state)
        return s1.union(self._analyze_alternative(alternative, state))

    def _analyze_alternative(self, alt: Node, state: TaintState) -> TaintState:
        # elif encadenado (Python) o `else if` (JS anidado dentro del else_clause).
        if alt.type == self.spec.if_type or alt.type == "elif_clause":
            return self._analyze_if(alt, state)
        for child in alt.named_children:
            if child.type in self.spec.block_types:
                return self._analyze_block(child, state)
            if child.type == self.spec.if_type:
                return self._analyze_if(child, state)
        return state

    def _analyze_stmt_or_block(self, node: Node, state: TaintState) -> TaintState:
        if node.type in self.spec.block_types:
            return self._analyze_block(node, state)
        return self._analyze_stmt(node, state)

    def _analyze_loop(self, node: Node, state: TaintState) -> TaintState:
        spec = self.spec
        body = node.child_by_field_name(spec.body_field)
        condition = node.child_by_field_name("condition")
        self._check_sinks(condition, state)

        entry = state
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is not None and right is not None:
            self._check_sinks(right, state)
            witness = self.is_tainted(right, state)
            if witness is not None:
                for name in self._target_names(left):
                    entry = entry.with_tainted(name, witness)

        if body is None:
            return entry

        current = entry
        for _ in range(_MAX_LOOP_ITERS):
            after = self._analyze_block(body, current)
            merged = current.union(after)
            if merged.locations() == current.locations():
                current = merged
                break
            current = merged
        return current.union(state)

    def _analyze_try(self, node: Node, state: TaintState) -> TaintState:
        spec = self.spec
        body = node.child_by_field_name(spec.body_field)
        after_body = self._analyze_block(body, state) if body is not None else state
        result = after_body
        # Los handlers pueden ejecutarse desde cualquier punto del try (conservador).
        entry_for_handlers = state.union(after_body)
        for child in node.named_children:
            if child.type in spec.catch_types:
                handler_block = self._first_block(child)
                if handler_block is not None:
                    result = result.union(self._analyze_block(handler_block, entry_for_handlers))
            elif child.type in spec.block_types and child is not body:
                result = result.union(self._analyze_block(child, entry_for_handlers))
        return result

    def _analyze_return(self, node: Node, state: TaintState) -> TaintState:
        expr = node.named_children[0] if node.named_children else None
        self._check_sinks(expr, state)
        if expr is not None and self.is_tainted(expr, state) is not None:
            self._return_tainted = True
        return state

    # -- asignaciones --------------------------------------------------------
    def _apply_var_decl(self, node: Node, state: TaintState) -> TaintState:
        for declarator in node.named_children:
            name = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            if name is None:
                continue
            self._check_sinks(value, state)
            state = self._assign(name, value, state)
        return state

    def _apply_assignment(self, node: Node, state: TaintState) -> TaintState:
        left = node.child_by_field_name(self.spec.assign_left_field)
        right = node.child_by_field_name(self.spec.assign_right_field)
        if left is None:
            return state
        augmented = "augmented" in node.type
        return self._assign(left, right, state, augmented=augmented)

    def _assign(
        self, target: Node, value: Node | None, state: TaintState, *, augmented: bool = False
    ) -> TaintState:
        witness = self.is_tainted(value, state) if value is not None else None
        if augmented and witness is None:
            witness = self.is_tainted(target, state)

        target = self.spec.unwrap_paren(target)

        if witness is not None:
            trace = (*witness, self._step(target, "propagado por asignación"))
        else:
            trace = ()

        # Contenedor: c.push(x)/c.append(x) — se resuelve en el nivel de la llamada,
        # no aquí. Aquí tratamos asignaciones normales y desestructuración.
        if target.type in self.spec.destructure_types or self._is_target_list(target):
            for name in self._target_names(target):
                state = state.with_tainted(name, trace) if witness else state.without(name)
            return state

        if target.type == self.spec.subscript_type:
            base = target.child_by_field_name(self.spec.subscript_object_field)
            base_loc = self._canonical(base) if base is not None else None
            if witness is not None and base_loc is not None:
                state = state.with_tainted(base_loc, trace)
            return state

        loc = self._canonical(target)
        if loc is None:
            return state
        return state.with_tainted(loc, trace) if witness else state.without(loc)

    def _is_target_list(self, node: Node) -> bool:
        return node.type in {"pattern_list", "tuple_pattern", "expression_list"}

    def _target_names(self, target: Node) -> list[str]:
        target = self.spec.unwrap_paren(target)
        if target.type == self.spec.name_type:
            return [target.text]
        return self.spec.destructure_names(target)

    def _first_block(self, node: Node) -> Node | None:
        for child in node.named_children:
            if child.type in self.spec.block_types:
                return child
        return None
