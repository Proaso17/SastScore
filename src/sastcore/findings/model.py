"""Modelo de datos de un hallazgo.

Es el centro de gravedad de toda la herramienta: reporters, dedup y baseline
dependen de él. Diseñado contra SARIF 2.1.0 desde el inicio (``DataFlowStep``
mapea 1:1 a ``threadFlowLocation``).

Convenciones de posición:
- ``start_line`` / ``end_line``: 1-indexadas (como los editores y SARIF).
- ``start_col`` / ``end_col``: 0-indexadas (offset dentro de la línea).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Severidad de un hallazgo, de mayor a menor."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(StrEnum):
    """Confianza del motor en que el hallazgo es real."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Engine(StrEnum):
    """Pasada que produjo el hallazgo."""

    regex = "regex"
    pattern = "pattern"
    taint = "taint"


#: Orden de severidad de mayor a menor, para comparaciones de umbral.
SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def severity_rank(severity: Severity) -> int:
    """Devuelve el rango numérico de una severidad (0 = más grave)."""
    return SEVERITY_ORDER.index(severity)


@dataclass(frozen=True, slots=True)
class Location:
    """Ubicación de un hallazgo en un fichero.

    Es una dataclass (no un modelo pydantic) a propósito: el taint crea gran cantidad de
    ``Location``/``DataFlowStep``, y crear/liberar tantos objetos pydantic-core corrompía
    la memoria en algunas plataformas. pydantic v2 sigue serializándolas dentro de Finding.
    """

    path: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int


@dataclass(frozen=True, slots=True)
class DataFlowStep:
    """Un paso en la traza de flujo de datos de un hallazgo de taint."""

    location: Location
    message: str


class Finding(BaseModel):
    """Una vulnerabilidad detectada."""

    rule_id: str
    message: str
    severity: Severity
    confidence: Confidence
    location: Location
    snippet: str
    engine: Engine
    cwe: list[str] = Field(default_factory=list)
    owasp: str | None = None
    data_flow: list[DataFlowStep] = Field(default_factory=list)
    fix_suggestion: str | None = None
    references: list[str] = Field(default_factory=list)
    fingerprint: str = ""

    def sort_key(self) -> tuple[str, int, int, str]:
        """Clave de orden determinista: (path, línea, columna, rule_id)."""
        return (
            self.location.path,
            self.location.start_line,
            self.location.start_col,
            self.rule_id,
        )
