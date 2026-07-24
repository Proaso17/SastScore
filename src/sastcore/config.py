"""Configuración de sastcore (``.sastcore.yml``).

Precedencia: **CLI > fichero > defaults**. La CLI resuelve cada opción tomando el valor
de línea de comandos si se pasó, si no el del fichero, y si no el default.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sastcore.findings.model import Confidence, Severity

CONFIG_FILENAME = ".sastcore.yml"


class OutputFormat(StrEnum):
    """Formatos de salida soportados por ``scan``."""

    console = "console"
    json = "json"
    sarif = "sarif"
    html = "html"
    markdown = "markdown"
    junit = "junit"


class ConfigError(ValueError):
    """El fichero de configuración no se pudo cargar o validar."""


class Config(BaseModel):
    """Opciones de ``.sastcore.yml``."""

    model_config = ConfigDict(extra="forbid")

    exclude: list[str] = Field(default_factory=list)
    fail_on: Severity | None = None
    format: OutputFormat | None = None
    min_confidence: Confidence | None = None
    disabled_rules: list[str] = Field(default_factory=list)


def find_config(start: Path) -> Path | None:
    """Busca ``.sastcore.yml`` en ``start`` (normalmente el directorio actual)."""
    candidate = start / CONFIG_FILENAME
    return candidate if candidate.is_file() else None


def load_config(path: Path) -> Config:
    """Carga y valida un fichero de configuración."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: se esperaba un mapa de opciones")
    try:
        return Config.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"{path}: configuración inválida: {exc}") from exc


def default_config_yaml() -> str:
    """Plantilla comentada para ``sastcore init`` (sin efecto por defecto)."""
    return (
        "# Configuración de sastcore.\n"
        "# Precedencia: opciones de la CLI > este fichero > valores por defecto.\n"
        "\n"
        "# Patrones extra a ignorar (además de .gitignore y .sastignore):\n"
        "exclude: []\n"
        "\n"
        "# Reglas a silenciar por id (p. ej. py.dangerous.exec):\n"
        "disabled_rules: []\n"
        "\n"
        "# Severidad mínima que provoca salida != 0 (CRITICAL, HIGH, MEDIUM, LOW, INFO):\n"
        "# fail_on: HIGH\n"
        "\n"
        "# Formato de salida por defecto (console, json, sarif, html, markdown, junit):\n"
        "# format: console\n"
        "\n"
        "# Confianza mínima para reportar un hallazgo (HIGH, MEDIUM, LOW):\n"
        "# min_confidence: MEDIUM\n"
    )
