"""Esquema pydantic de una regla."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sastcore.discovery.languages import Language
from sastcore.findings.model import Confidence, Severity


class RuleTests(BaseModel):
    """Rutas a los fixtures obligatorios de una regla (relativas a la raíz del repo)."""

    model_config = ConfigDict(extra="forbid")

    bad: str
    good: str


class Rule(BaseModel):
    """Una regla de análisis."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    id: str
    languages: list[Language]
    mode: Literal["regex", "pattern", "taint"]
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    message: str
    cwe: list[str] = Field(default_factory=list)
    owasp: str | None = None
    pattern: str | None = None
    pattern_either: list[str] = Field(default_factory=list, alias="pattern-either")
    fix_suggestion: str | None = None
    references: list[str] = Field(default_factory=list)
    tests: RuleTests

    @model_validator(mode="after")
    def _check_pattern_mode(self) -> Rule:
        if self.mode == "pattern" and not self.pattern and not self.pattern_either:
            raise ValueError(
                f"regla {self.id}: el modo 'pattern' requiere 'pattern' o 'pattern-either'"
            )
        return self

    def patterns(self) -> list[str]:
        """Devuelve todos los patrones de la regla (``pattern`` + ``pattern-either``)."""
        result: list[str] = []
        if self.pattern is not None:
            result.append(self.pattern)
        result.extend(self.pattern_either)
        return result
