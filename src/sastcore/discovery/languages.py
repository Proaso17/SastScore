"""Detección de lenguaje por extensión y, en su defecto, por shebang."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path


class Language(StrEnum):
    """Lenguajes soportados en el MVP."""

    javascript = "javascript"
    typescript = "typescript"
    python = "python"


_BY_EXTENSION: dict[str, Language] = {
    ".js": Language.javascript,
    ".jsx": Language.javascript,
    ".mjs": Language.javascript,
    ".cjs": Language.javascript,
    ".ts": Language.typescript,
    ".tsx": Language.typescript,
    ".mts": Language.typescript,
    ".cts": Language.typescript,
    ".py": Language.python,
    ".pyi": Language.python,
}

_SHEBANG_TOKENS: tuple[tuple[str, Language], ...] = (
    ("python", Language.python),
    ("node", Language.javascript),
)


def detect_language(path: Path, first_line: str | None = None) -> Language | None:
    """Detecta el lenguaje de un fichero.

    Primero por extensión; si no hay match y ``first_line`` es un shebang, se
    infiere del intérprete. Devuelve ``None`` si no se reconoce.
    """
    language = _BY_EXTENSION.get(path.suffix.lower())
    if language is not None:
        return language

    if first_line and first_line.startswith("#!"):
        lowered = first_line.lower()
        for token, lang in _SHEBANG_TOKENS:
            if token in lowered:
                return lang

    return None
