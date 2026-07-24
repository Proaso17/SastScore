"""Fixtures compartidas de la suite de tests."""

from __future__ import annotations

import gc
import os
import sys

import pytest
from typer.testing import CliRunner

# El binding de tree-sitter crashea si el GC cíclico escanea/recolecta sus objetos (que
# forman ciclos irrompibles) en esta plataforma. Se desactiva el GC durante la sesión de
# tests; los objetos de tree-sitter se abandonan y el SO recupera la memoria al salir.
gc.disable()


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Sale con os._exit para evitar el crash del binding al recolectar en el teardown.

    Como os._exit se adelanta al resumen final de pytest, se imprime uno manual.
    """
    passed = session.testscollected - session.testsfailed
    print(
        f"\n=== {passed} passed, {session.testsfailed} failed (exit {int(exitstatus)}) ===",
        flush=True,
    )
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(int(exitstatus))


@pytest.fixture
def runner() -> CliRunner:
    """Runner de Typer para invocar la CLI en tests."""
    return CliRunner()
