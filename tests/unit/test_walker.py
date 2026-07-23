"""Tests del recorrido de ficheros (discovery)."""

from __future__ import annotations

from pathlib import Path

from sastcore.discovery.walker import FileWalker, is_binary


def test_lists_text_files(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("print(1)\n", encoding="utf-8")
    (tmp_path / "b.js").write_text("console.log(1)\n", encoding="utf-8")
    names = sorted(p.name for p in FileWalker(tmp_path).walk())
    assert names == ["a.py", "b.js"]


def test_respects_gitignore(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("ignored/\n*.log\n", encoding="utf-8")
    (tmp_path / "keep.py").write_text("x\n", encoding="utf-8")
    (tmp_path / "skip.log").write_text("x\n", encoding="utf-8")
    ignored = tmp_path / "ignored"
    ignored.mkdir()
    (ignored / "secret.py").write_text("x\n", encoding="utf-8")

    found = {p.relative_to(tmp_path).as_posix() for p in FileWalker(tmp_path).walk()}
    assert "keep.py" in found
    assert "skip.log" not in found
    assert "ignored/secret.py" not in found


def test_respects_sastignore(tmp_path: Path) -> None:
    (tmp_path / ".sastignore").write_text("vendor/\n", encoding="utf-8")
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "lib.py").write_text("x\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("x\n", encoding="utf-8")

    found = {p.relative_to(tmp_path).as_posix() for p in FileWalker(tmp_path).walk()}
    assert "app.py" in found
    assert "vendor/lib.py" not in found


def test_skips_binary(tmp_path: Path) -> None:
    (tmp_path / "bin.dat").write_bytes(b"\x00\x01\x02\x00")
    (tmp_path / "ok.py").write_text("x\n", encoding="utf-8")
    names = {p.name for p in FileWalker(tmp_path).walk()}
    assert "ok.py" in names
    assert "bin.dat" not in names


def test_skips_large_files(tmp_path: Path) -> None:
    (tmp_path / "big.py").write_text("x" * 100, encoding="utf-8")
    (tmp_path / "small.py").write_text("y\n", encoding="utf-8")
    names = {p.name for p in FileWalker(tmp_path, max_bytes=10).walk()}
    assert "small.py" in names
    assert "big.py" not in names


def test_prunes_default_ignored_dirs(tmp_path: Path) -> None:
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    (node_modules / "dep.js").write_text("x\n", encoding="utf-8")
    (tmp_path / "index.js").write_text("x\n", encoding="utf-8")
    names = {p.name for p in FileWalker(tmp_path).walk()}
    assert "index.js" in names
    assert "dep.js" not in names


def test_is_binary(tmp_path: Path) -> None:
    text = tmp_path / "t.txt"
    text.write_text("hello\n", encoding="utf-8")
    binary = tmp_path / "b.bin"
    binary.write_bytes(b"\x00\xff")
    assert is_binary(binary) is True
    assert is_binary(text) is False
