"""Fixtures compartidas de la suite de tests."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner


@pytest.fixture
def runner() -> CliRunner:
    """Runner de Typer para invocar la CLI en tests."""
    return CliRunner()
