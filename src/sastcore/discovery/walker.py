"""Recorrido de ficheros a analizar.

Respeta ``.gitignore`` y ``.sastignore`` (raíz), poda directorios ignorados durante
el recorrido, salta binarios y ficheros por encima de un límite de tamaño.

``walk()`` devuelve pares ``(ruta, ruta_relativa_posix)``: el walker ya conoce la raíz,
así que calcula la ruta relativa una sola vez (con operaciones de string, evitando el
coste de ``Path.relative_to``) y las pasadas no la recomputan.

Limitación conocida (MVP): solo se leen los ficheros de ignore de la raíz; los
``.gitignore`` anidados en subdirectorios no se combinan todavía.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pathspec

#: Patrones ignorados siempre, independientemente de los ficheros de ignore.
_DEFAULT_IGNORES: tuple[str, ...] = (
    ".git/",
    ".hg/",
    ".svn/",
    "node_modules/",
    ".venv/",
    "venv/",
    "env/",
    "__pycache__/",
    ".mypy_cache/",
    ".ruff_cache/",
    ".pytest_cache/",
    "dist/",
    "build/",
    "*.min.js",
    "*.map",
)

#: Extensiones que damos por texto: nos ahorramos abrir el fichero para el test binario.
_TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".mts",
        ".cts",
        ".json",
        ".yml",
        ".yaml",
        ".txt",
        ".md",
        ".cfg",
        ".ini",
        ".toml",
    }
)

_DEFAULT_MAX_BYTES = 5_000_000


def _read_ignore_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return path.read_text(encoding="utf-8", errors="ignore").splitlines()


def is_binary(path: Path, sample_size: int = 8192) -> bool:
    """Heurística: un byte NUL en la muestra inicial marca el fichero como binario."""
    try:
        with path.open("rb") as handle:
            chunk = handle.read(sample_size)
    except OSError:
        return True
    return b"\x00" in chunk


class FileWalker:
    """Enumera los ficheros de texto candidatos bajo ``root``, de forma determinista."""

    def __init__(
        self,
        root: Path,
        *,
        max_bytes: int = _DEFAULT_MAX_BYTES,
        respect_gitignore: bool = True,
    ) -> None:
        self.root = root
        self.max_bytes = max_bytes

        patterns: list[str] = list(_DEFAULT_IGNORES)
        if respect_gitignore:
            patterns += _read_ignore_lines(root / ".gitignore")
        patterns += _read_ignore_lines(root / ".sastignore")
        self._spec = pathspec.PathSpec.from_lines("gitignore", patterns)

    def _is_ignored(self, rel_posix: str) -> bool:
        return self._spec.match_file(rel_posix)

    def walk(self) -> Iterator[tuple[Path, str]]:
        """Genera pares ``(ruta, ruta_relativa_posix)`` ordenados de forma determinista."""
        yield from sorted(self._iter_files(), key=lambda pair: pair[1])

    def _iter_files(self) -> Iterator[tuple[Path, str]]:
        root_len = len(str(self.root))
        for dirpath, dirnames, filenames in os.walk(self.root):
            rel_dir = dirpath[root_len:].replace(os.sep, "/").strip("/")

            # Poda in-place los directorios ignorados (evita descender en ellos).
            kept: list[str] = []
            for name in dirnames:
                rel = f"{rel_dir}/{name}" if rel_dir else name
                if not self._is_ignored(f"{rel}/"):
                    kept.append(name)
            dirnames[:] = kept

            for name in filenames:
                rel = f"{rel_dir}/{name}" if rel_dir else name
                if self._is_ignored(rel):
                    continue
                path = Path(dirpath) / name
                try:
                    if path.stat().st_size > self.max_bytes:
                        continue
                except OSError:
                    continue
                if path.suffix.lower() not in _TEXT_EXTENSIONS and is_binary(path):
                    continue
                yield (path, rel)
