"""Tests del cargador y validador de reglas."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastcore.rules.loader import (
    RuleLoadError,
    default_rulepacks_dir,
    load_rulepack_file,
    load_rulepacks,
)
from sastcore.rules.model import Rule

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_loads_default_rulepacks() -> None:
    rules = load_rulepacks(default_rulepacks_dir(), fixtures_root=_REPO_ROOT, require_fixtures=True)
    assert len(rules) >= 5
    assert all(isinstance(rule, Rule) for rule in rules)


def test_rejects_rule_without_fixtures(tmp_path: Path) -> None:
    yml = tmp_path / "bad.yml"
    yml.write_text(
        "- id: x.test\n"
        "  languages: [python]\n"
        "  mode: pattern\n"
        "  severity: HIGH\n"
        '  message: "m"\n'
        '  pattern: "eval($X)"\n'
        "  tests:\n"
        "    bad: does/not/exist_bad.py\n"
        "    good: does/not/exist_good.py\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleLoadError):
        load_rulepack_file(yml, fixtures_root=tmp_path, require_fixtures=True)


def test_pattern_mode_requires_a_pattern(tmp_path: Path) -> None:
    yml = tmp_path / "nopattern.yml"
    yml.write_text(
        "- id: x.nopattern\n"
        "  languages: [python]\n"
        "  mode: pattern\n"
        "  severity: HIGH\n"
        '  message: "m"\n'
        "  tests:\n"
        "    bad: a\n"
        "    good: b\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleLoadError):
        load_rulepack_file(yml, fixtures_root=tmp_path, require_fixtures=False)


def test_rejects_unknown_field(tmp_path: Path) -> None:
    yml = tmp_path / "typo.yml"
    yml.write_text(
        "- id: x.typo\n"
        "  languages: [python]\n"
        "  mode: pattern\n"
        "  severity: HIGH\n"
        '  message: "m"\n'
        '  pattern: "eval($X)"\n'
        "  serverity: HIGH\n"  # typo
        "  tests:\n"
        "    bad: a\n"
        "    good: b\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleLoadError):
        load_rulepack_file(yml, fixtures_root=tmp_path, require_fixtures=False)
