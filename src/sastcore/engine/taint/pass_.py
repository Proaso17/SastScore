"""Pasada de taint: por cada regla ``mode: taint``, analiza cada función del fichero."""

from __future__ import annotations

from collections.abc import Sequence

from sastcore.discovery.languages import Language
from sastcore.engine.pattern.compile import compile_pattern
from sastcore.engine.taint.adapters import spec_for
from sastcore.engine.taint.propagation import Engine, SinkSpec, TaintFinding
from sastcore.engine.taint.state import TaintState
from sastcore.engine.taint.summaries import compute_summaries
from sastcore.findings.fingerprint import compute_fingerprint
from sastcore.findings.model import Engine as EngineKind
from sastcore.findings.model import Finding, Location
from sastcore.parsing.ast import Node
from sastcore.rules.model import Rule

_SNIPPET_CONTEXT = 2


def _snippet(lines: Sequence[str], match_line: int) -> str:
    start = max(0, match_line - 1 - _SNIPPET_CONTEXT)
    end = min(len(lines), match_line + _SNIPPET_CONTEXT)
    return "\n".join(lines[start:end])


class TaintPass:
    """Aplica las reglas de taint al AST de un fichero."""

    def __init__(self, rules: Sequence[Rule]) -> None:
        self._rules = [rule for rule in rules if rule.mode == "taint"]

    def scan(
        self,
        *,
        rel_path: str,
        tree: Node,
        file_lines: Sequence[str],
        language: Language,
    ) -> list[Finding]:
        rules = [rule for rule in self._rules if language in rule.languages]
        if not rules:
            return []

        spec = spec_for(language)
        named_functions: list[tuple[str, Node]] = []
        scopes: list[Node] = []
        for node in tree.walk_preorder():
            if node.type in spec.function_types:
                body = node.child_by_field_name(spec.body_field)
                if body is not None:
                    scopes.append(body)
                name_node = node.child_by_field_name("name")
                if name_node is not None:
                    named_functions.append((name_node.text, node))
        scopes.append(tree)  # ámbito de nivel de módulo

        summaries = compute_summaries(
            named_functions, spec=spec, rel_path=rel_path, file_lines=file_lines
        )

        findings: list[Finding] = []
        occurrences: dict[str, int] = {}
        for rule in rules:
            sources = [compile_pattern(language, s.pattern) for s in rule.sources]
            sanitizers = [compile_pattern(language, s.pattern) for s in rule.sanitizers]
            sinks = [
                SinkSpec(compile_pattern(language, s.pattern), s.taint_arg, rule.id)
                for s in rule.sinks
            ]
            for scope in scopes:
                engine = Engine(
                    spec=spec,
                    rel_path=rel_path,
                    file_lines=file_lines,
                    sources=sources,
                    sanitizers=sanitizers,
                    sinks=sinks,
                    summaries=summaries,
                )
                result = engine.run(scope, TaintState())
                for taint_finding in result.findings:
                    findings.append(
                        self._to_finding(rule, taint_finding, rel_path, file_lines, occurrences)
                    )
        return findings

    def _to_finding(
        self,
        rule: Rule,
        taint_finding: TaintFinding,
        rel_path: str,
        file_lines: Sequence[str],
        occurrences: dict[str, int],
    ) -> Finding:
        node = taint_finding.sink_node
        start_row, start_col = node.start_point
        end_row, end_col = node.end_point
        start_line = start_row + 1

        index = occurrences.get(rule.id, 0)
        occurrences[rule.id] = index + 1
        fingerprint = compute_fingerprint(
            rule_id=rule.id,
            file_lines=file_lines,
            match_line=start_line,
            occurrence_index=index,
        )
        return Finding(
            rule_id=rule.id,
            message=rule.message,
            severity=rule.severity,
            confidence=rule.confidence,
            location=Location(
                path=rel_path,
                start_line=start_line,
                start_col=start_col,
                end_line=end_row + 1,
                end_col=end_col,
            ),
            snippet=_snippet(file_lines, start_line),
            engine=EngineKind.taint,
            cwe=list(rule.cwe),
            owasp=rule.owasp,
            data_flow=taint_finding.data_flow,
            fix_suggestion=rule.fix_suggestion,
            references=list(rule.references),
            fingerprint=fingerprint,
        )


def default_taint_pass() -> TaintPass:
    """Construye una TaintPass con los rulepacks empaquetados."""
    from sastcore.rules.loader import default_rulepacks_dir, load_rulepacks

    rulepacks = default_rulepacks_dir()
    rules = load_rulepacks(rulepacks, fixtures_root=rulepacks, require_fixtures=False)
    return TaintPass(rules)
