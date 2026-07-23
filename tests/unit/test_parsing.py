"""Tests del parsing con tree-sitter y el wrapper AST."""

from __future__ import annotations

from sastcore.discovery.languages import Language
from sastcore.parsing.ast import parse
from sastcore.parsing.cache import ParseCache


def test_parse_python_call() -> None:
    root = parse(Language.python, "import os\nos.system(x)\n")
    assert root.type == "module"
    assert not root.has_error
    calls = [n for n in root.walk_preorder() if n.type == "call"]
    assert len(calls) == 1
    fn = calls[0].child_by_field_name("function")
    assert fn is not None
    assert fn.text == "os.system"


def test_parse_javascript_call() -> None:
    root = parse(Language.javascript, "eval(userInput);")
    calls = [n for n in root.walk_preorder() if n.type == "call_expression"]
    assert len(calls) == 1
    fn = calls[0].child_by_field_name("function")
    assert fn is not None
    assert fn.text == "eval"


def test_structure_ignores_formatting_and_comments() -> None:
    a = parse(Language.python, "os.system(x)")
    b = parse(Language.python, "os.system(  x  )  # comment")
    a_types = [n.type for n in a.walk_preorder() if n.is_named and n.type != "comment"]
    b_types = [n.type for n in b.walk_preorder() if n.is_named and n.type != "comment"]
    assert a_types == b_types


def test_syntax_error_does_not_raise() -> None:
    root = parse(Language.python, "def (:\n")
    assert root.has_error


def test_positions_are_zero_indexed() -> None:
    root = parse(Language.python, "x = 1\n")
    assert root.start_point == (0, 0)


def test_parse_cache_returns_same_object() -> None:
    cache = ParseCache()
    first = cache.get(Language.python, "os.system(x)\n")
    second = cache.get(Language.python, "os.system(x)\n")
    assert first is second
