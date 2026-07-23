"""Índice de reglas por lenguaje y modo."""

from __future__ import annotations

from sastcore.discovery.languages import Language
from sastcore.rules.model import Rule


class RuleRegistry:
    """Consulta rápida de reglas por lenguaje/modo."""

    def __init__(self, rules: list[Rule]) -> None:
        self._rules = list(rules)

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def pattern_rules_for(self, language: Language) -> list[Rule]:
        return [
            rule for rule in self._rules if rule.mode == "pattern" and language in rule.languages
        ]
