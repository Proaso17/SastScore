"""Tests de la detección de lenguaje."""

from __future__ import annotations

from pathlib import Path

from sastcore.discovery.languages import Language, detect_language


def test_by_extension() -> None:
    assert detect_language(Path("a.py")) is Language.python
    assert detect_language(Path("a.ts")) is Language.typescript
    assert detect_language(Path("a.tsx")) is Language.typescript
    assert detect_language(Path("a.jsx")) is Language.javascript
    assert detect_language(Path("a.mjs")) is Language.javascript


def test_unknown_extension_returns_none() -> None:
    assert detect_language(Path("a.txt")) is None
    assert detect_language(Path("Makefile")) is None


def test_shebang_python() -> None:
    assert detect_language(Path("script"), "#!/usr/bin/env python3") is Language.python


def test_shebang_node() -> None:
    assert detect_language(Path("script"), "#!/usr/bin/env node") is Language.javascript


def test_extension_wins_over_shebang() -> None:
    assert detect_language(Path("a.py"), "#!/usr/bin/env node") is Language.python
