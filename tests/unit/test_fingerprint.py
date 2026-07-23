"""Tests del fingerprint estilo partialFingerprints (ADR-0002)."""

from __future__ import annotations

from sastcore.findings.fingerprint import compute_fingerprint


def test_stable_when_block_moves_beyond_window() -> None:
    # El mismo bloque con contexto idéntico a ±window, movido por líneas lejanas.
    neighbors = ["# c3", "# c2", "# c1", "    token = 'x'", "# d1", "# d2", "# d3"]
    token_offset = neighbors.index("    token = 'x'")
    file_a = ["import a", *neighbors]
    file_b = ["import a", "import b", "import c", "import d", "import e", *neighbors]
    line_a = 1 + token_offset + 1
    line_b = 5 + token_offset + 1
    fp_a = compute_fingerprint(rule_id="r", file_lines=file_a, match_line=line_a, window=3)
    fp_b = compute_fingerprint(rule_id="r", file_lines=file_b, match_line=line_b, window=3)
    assert fp_a == fp_b


def test_changes_with_rule_id() -> None:
    lines = ["a", "b", "c"]
    fp1 = compute_fingerprint(rule_id="r1", file_lines=lines, match_line=2)
    fp2 = compute_fingerprint(rule_id="r2", file_lines=lines, match_line=2)
    assert fp1 != fp2


def test_occurrence_index_disambiguates() -> None:
    lines = ["x", "x", "x", "x", "x"]
    fp0 = compute_fingerprint(rule_id="r", file_lines=lines, match_line=3, occurrence_index=0)
    fp1 = compute_fingerprint(rule_id="r", file_lines=lines, match_line=3, occurrence_index=1)
    assert fp0 != fp1


def test_ignores_whitespace_and_formatting() -> None:
    a = ["def f():", "    token = 'x'", "    return token"]
    b = ["def   f():", "\ttoken   =   'x'", "  return   token"]
    fp_a = compute_fingerprint(rule_id="r", file_lines=a, match_line=2)
    fp_b = compute_fingerprint(rule_id="r", file_lines=b, match_line=2)
    assert fp_a == fp_b


def test_returns_hex_sha256() -> None:
    fp = compute_fingerprint(rule_id="r", file_lines=["a"], match_line=1)
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)
