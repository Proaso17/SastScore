"""Tests del motor de taint: los 5 casos obligatorios de la sección 8 + traza."""

from __future__ import annotations

from sastcore.discovery.languages import Language
from sastcore.engine.taint.pass_ import TaintPass
from sastcore.findings.model import Finding
from sastcore.parsing.ast import parse
from sastcore.rules.model import Rule


def _rule(
    language: Language,
    sources: list[str],
    sinks: list[str],
    sanitizers: list[str] | None = None,
) -> Rule:
    return Rule.model_validate(
        {
            "id": "test.taint",
            "languages": [language.value],
            "mode": "taint",
            "severity": "HIGH",
            "message": "flujo tainted",
            "sources": [{"pattern": s} for s in sources],
            "sanitizers": [{"pattern": s} for s in (sanitizers or [])],
            "sinks": [{"pattern": s, "taint_arg": 0} for s in sinks],
            "tests": {"bad": "x", "good": "y"},
        }
    )


_PY = _rule(
    Language.python,
    sources=["request.args", "request.form"],
    sinks=["cursor.execute($Q)", "os.system($X)"],
    sanitizers=["escape($X)", "int($X)"],
)


def _run(language: Language, code: str, rule: Rule) -> list[Finding]:
    return TaintPass([rule]).scan(
        rel_path="t",
        tree=parse(language, code),
        file_lines=code.splitlines(),
        language=language,
    )


def test_source_to_sink() -> None:
    code = "def v():\n    q = request.args.get('id')\n    cursor.execute(q)\n"
    assert len(_run(Language.python, code, _PY)) == 1


def test_reassignment_cleans() -> None:
    code = "def v():\n    q = request.args.get('id')\n    q = 'safe'\n    cursor.execute(q)\n"
    assert _run(Language.python, code, _PY) == []


def test_sanitizer_in_one_branch_still_reports() -> None:
    code = (
        "def v(c):\n"
        "    q = request.args.get('id')\n"
        "    if c:\n"
        "        q = escape(q)\n"
        "    cursor.execute(q)\n"
    )
    assert len(_run(Language.python, code, _PY)) == 1


def test_sanitizer_dominating_all_branches_is_clean() -> None:
    code = (
        "def v(c):\n"
        "    q = request.args.get('id')\n"
        "    if c:\n"
        "        q = escape(q)\n"
        "    else:\n"
        "        q = escape(q)\n"
        "    cursor.execute(q)\n"
    )
    assert _run(Language.python, code, _PY) == []


def test_taint_in_loop() -> None:
    code = (
        "def v():\n"
        "    q = ''\n"
        "    for it in request.args.getlist('x'):\n"
        "        q = it\n"
        "    cursor.execute(q)\n"
    )
    assert len(_run(Language.python, code, _PY)) == 1


def test_taint_through_array() -> None:
    code = (
        "def v():\n"
        "    arr = []\n"
        "    arr.append(request.args.get('x'))\n"
        "    cursor.execute(arr[0])\n"
    )
    assert len(_run(Language.python, code, _PY)) == 1


def test_interprocedural_summary() -> None:
    code = (
        "def wrap(u):\n"
        "    return u + ''\n"
        "def v():\n"
        "    q = request.args.get('id')\n"
        "    y = wrap(q)\n"
        "    cursor.execute(y)\n"
    )
    assert len(_run(Language.python, code, _PY)) == 1


def test_destructuring_javascript() -> None:
    rule = _rule(Language.javascript, sources=["req.query"], sinks=["conn.query($Q)"])
    code = "function v(req) {\n  const { id } = req.query;\n  conn.query(id);\n}\n"
    assert len(_run(Language.javascript, code, rule)) == 1


def test_data_flow_trace_has_source_and_sink() -> None:
    code = "def v():\n    q = request.args.get('id')\n    y = q\n    cursor.execute(y)\n"
    finding = _run(Language.python, code, _PY)[0]
    assert len(finding.data_flow) >= 2
    assert "source" in finding.data_flow[0].message
    assert "sink" in finding.data_flow[-1].message
    assert finding.data_flow[0].location.start_line == 2
    assert finding.data_flow[-1].location.start_line == 4
