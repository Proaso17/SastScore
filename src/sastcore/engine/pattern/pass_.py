"""Pasada de patrones: aplica reglas ``mode: pattern`` al AST de un fichero."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from sastcore.discovery.languages import Language
from sastcore.engine.pattern.compile import CompiledPattern, compile_pattern
from sastcore.engine.pattern.matcher import match_node, root_is_metavar
from sastcore.findings.fingerprint import compute_fingerprint
from sastcore.findings.model import Engine, Finding, Location
from sastcore.parsing.ast import Node
from sastcore.rules.model import Rule

_SNIPPET_CONTEXT = 2


def _snippet(lines: Sequence[str], match_line: int) -> str:
    start = max(0, match_line - 1 - _SNIPPET_CONTEXT)
    end = min(len(lines), match_line + _SNIPPET_CONTEXT)
    return "\n".join(lines[start:end])


@dataclass(frozen=True)
class _CompiledRule:
    rule: Rule
    language: Language
    patterns: tuple[CompiledPattern, ...]


class PatternPass:
    """Precompila las reglas de patrón y las aplica al árbol de un fichero."""

    def __init__(self, rules: Sequence[Rule]) -> None:
        self._compiled: list[_CompiledRule] = []
        for rule in rules:
            if rule.mode != "pattern":
                continue
            for language in rule.languages:
                compiled = tuple(compile_pattern(language, p) for p in rule.patterns())
                self._compiled.append(_CompiledRule(rule, language, compiled))

    def scan(
        self,
        *,
        rel_path: str,
        tree: Node,
        file_lines: Sequence[str],
        language: Language,
    ) -> list[Finding]:
        findings: list[Finding] = []
        occurrences: dict[str, int] = {}

        # Un solo recorrido del árbol por fichero: indexamos los nodos por tipo y luego
        # cada patrón solo se prueba contra los nodos de su tipo raíz.
        nodes_by_type: dict[str, list[Node]] = defaultdict(list)
        for node in tree.walk_preorder():
            nodes_by_type[node.type].append(node)

        for entry in self._compiled:
            if entry.language != language:
                continue
            for pattern in entry.patterns:
                if root_is_metavar(pattern):
                    candidates: list[Node] = [n for nodes in nodes_by_type.values() for n in nodes]
                else:
                    candidates = nodes_by_type.get(pattern.root.type, [])
                for node in candidates:
                    bindings = match_node(pattern, node)
                    if bindings is None:
                        continue
                    start_row, start_col = node.start_point
                    end_row, end_col = node.end_point
                    start_line = start_row + 1

                    index = occurrences.get(entry.rule.id, 0)
                    occurrences[entry.rule.id] = index + 1
                    fingerprint = compute_fingerprint(
                        rule_id=entry.rule.id,
                        file_lines=file_lines,
                        match_line=start_line,
                        occurrence_index=index,
                    )

                    findings.append(
                        Finding(
                            rule_id=entry.rule.id,
                            message=entry.rule.message,
                            severity=entry.rule.severity,
                            confidence=entry.rule.confidence,
                            location=Location(
                                path=rel_path,
                                start_line=start_line,
                                start_col=start_col,
                                end_line=end_row + 1,
                                end_col=end_col,
                            ),
                            snippet=_snippet(file_lines, start_line),
                            engine=Engine.pattern,
                            cwe=list(entry.rule.cwe),
                            owasp=entry.rule.owasp,
                            data_flow=[],
                            fix_suggestion=entry.rule.fix_suggestion,
                            references=list(entry.rule.references),
                            fingerprint=fingerprint,
                        )
                    )

        return findings


def default_pattern_pass() -> PatternPass:
    """Construye una PatternPass con los rulepacks empaquetados."""
    from sastcore.rules.loader import default_rulepacks_dir, load_rulepacks

    rulepacks = default_rulepacks_dir()
    rules = load_rulepacks(rulepacks, fixtures_root=rulepacks, require_fixtures=False)
    return PatternPass(rules)
