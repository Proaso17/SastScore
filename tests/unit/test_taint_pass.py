"""Tests parametrizados de la pasada de taint contra los fixtures bad/good."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastcore.discovery.languages import detect_language
from sastcore.engine.taint.pass_ import TaintPass
from sastcore.parsing.ast import parse
from sastcore.rules.loader import default_rulepacks_dir, load_rulepacks
from sastcore.rules.model import Rule

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RULES = [
    rule
    for rule in load_rulepacks(
        default_rulepacks_dir(), fixtures_root=_REPO_ROOT, require_fixtures=True
    )
    if rule.mode == "taint"
]
_IDS = [rule.id for rule in _RULES]


def _scan(rule: Rule, fixture: Path) -> list[str]:
    content = fixture.read_text(encoding="utf-8")
    language = detect_language(fixture)
    assert language is not None, f"lenguaje no detectado para {fixture}"
    tree = parse(language, content)
    findings = TaintPass([rule]).scan(
        rel_path=fixture.name,
        tree=tree,
        file_lines=content.splitlines(),
        language=language,
    )
    return [finding.rule_id for finding in findings]


def test_there_are_taint_rules() -> None:
    assert _RULES, "no se cargó ninguna regla de taint"


@pytest.mark.parametrize("rule", _RULES, ids=_IDS)
def test_bad_fixture_triggers(rule: Rule) -> None:
    fired = _scan(rule, _REPO_ROOT / rule.tests.bad)
    assert rule.id in fired, f"{rule.id} no disparó en su fixture bad"


@pytest.mark.parametrize("rule", _RULES, ids=_IDS)
def test_good_fixture_is_clean(rule: Rule) -> None:
    fired = _scan(rule, _REPO_ROOT / rule.tests.good)
    assert rule.id not in fired, f"{rule.id} produjo un falso positivo en su fixture good"
