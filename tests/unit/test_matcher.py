"""Tests del motor de matching estructural."""

from __future__ import annotations

import pytest

from sastcore.discovery.languages import Language
from sastcore.engine.pattern.compile import PatternError, compile_pattern
from sastcore.engine.pattern.matcher import Match, find_matches
from sastcore.parsing.ast import parse


def _matches(language: Language, pattern: str, code: str) -> list[Match]:
    compiled = compile_pattern(language, pattern)
    return find_matches(compiled, parse(language, code))


def test_matches_eval_javascript() -> None:
    matches = _matches(Language.javascript, "eval($X)", "eval(userInput);")
    assert len(matches) == 1
    assert matches[0].bindings["X"] == "userInput"


def test_matches_os_system_python() -> None:
    matches = _matches(Language.python, "os.system($X)", "import os\nos.system(cmd)\n")
    assert len(matches) == 1
    assert matches[0].bindings["X"] == "cmd"


def test_ignores_formatting_and_comments() -> None:
    matches = _matches(Language.python, "os.system($X)", "os.system(  cmd  )  # peligro")
    assert len(matches) == 1


def test_no_match_for_different_function() -> None:
    assert _matches(Language.python, "os.system($X)", "os.popen(cmd)") == []


def test_metavariable_consistency() -> None:
    assert len(_matches(Language.python, "eq($X, $X)", "eq(a, a)")) == 1
    assert _matches(Language.python, "eq($X, $X)", "eq(a, b)") == []


def test_ellipsis_in_arguments() -> None:
    matches = _matches(Language.python, "log($X, ...)", "log(msg, a, b, c)")
    assert len(matches) == 1
    assert matches[0].bindings["X"] == "msg"


def test_ellipsis_matches_zero_args() -> None:
    assert len(_matches(Language.python, "f(...)", "f()")) == 1


def test_string_literal_quote_insensitive() -> None:
    assert len(_matches(Language.javascript, 'f("x")', "f('x');")) == 1


def test_string_literal_content_must_match() -> None:
    assert _matches(Language.javascript, 'f("x")', "f('y');") == []


def test_invalid_pattern_raises() -> None:
    with pytest.raises(PatternError):
        compile_pattern(Language.python, "def (:")
