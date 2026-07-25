"""Pasada de secretos: aplica el catálogo de detectores a un fichero.

Nota de seguridad: el valor del secreto **nunca** se almacena en el ``Finding``; el
``snippet`` se enmascara para no filtrar credenciales a los informes (JSON, SARIF,
HTML, etc.).
"""

from __future__ import annotations

from collections.abc import Sequence

from sastcore.engine.secrets.entropy import shannon_entropy
from sastcore.engine.secrets.patterns import DETECTORS, SecretDetector
from sastcore.findings.fingerprint import compute_fingerprint
from sastcore.findings.model import Engine, Finding, Location

_SNIPPET_CONTEXT = 2


def _offset_to_linecol(content: str, offset: int) -> tuple[int, int]:
    """Convierte un offset absoluto en (línea 1-indexada, columna 0-indexada)."""
    prefix = content[:offset]
    line = prefix.count("\n") + 1
    col = offset - (prefix.rfind("\n") + 1)
    return line, col


def _mask(value: str) -> str:
    """Enmascara un secreto conservando pistas mínimas para identificarlo."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def _masked_snippet(lines: Sequence[str], match_line: int, value: str) -> str:
    """Devuelve ±contexto líneas alrededor del match, con el secreto enmascarado."""
    start = max(0, match_line - 1 - _SNIPPET_CONTEXT)
    end = min(len(lines), match_line + _SNIPPET_CONTEXT)
    rendered: list[str] = []
    masked = _mask(value)
    for i in range(start, end):
        text = lines[i]
        if i == match_line - 1:
            text = text.replace(value, masked)
        rendered.append(text)
    return "\n".join(rendered)


class SecretsPass:
    """Detecta secretos hardcodeados en el contenido de un fichero."""

    def __init__(self, detectors: Sequence[SecretDetector] | None = None) -> None:
        self._detectors = tuple(detectors) if detectors is not None else DETECTORS

    def scan_file(self, *, rel_path: str, content: str) -> list[Finding]:
        """Aplica todos los detectores y devuelve los hallazgos del fichero."""
        lines = content.splitlines()
        findings: list[Finding] = []
        occurrences: dict[str, int] = {}

        for detector in self._detectors:
            for match in detector.regex.finditer(content):
                value = match.group(detector.group)
                if (
                    detector.min_entropy is not None
                    and shannon_entropy(value) < detector.min_entropy
                ):
                    continue
                if detector.validate is not None and not detector.validate(value):
                    continue

                start_line, start_col = _offset_to_linecol(content, match.start(detector.group))
                end_line, end_col = _offset_to_linecol(content, match.end(detector.group))

                index = occurrences.get(detector.rule_id, 0)
                occurrences[detector.rule_id] = index + 1
                fingerprint = compute_fingerprint(
                    rule_id=detector.rule_id,
                    file_lines=lines,
                    match_line=start_line,
                    occurrence_index=index,
                )

                findings.append(
                    Finding(
                        rule_id=detector.rule_id,
                        message=detector.description,
                        severity=detector.severity,
                        confidence=detector.confidence,
                        location=Location(
                            path=rel_path,
                            start_line=start_line,
                            start_col=start_col,
                            end_line=end_line,
                            end_col=end_col,
                        ),
                        snippet=_masked_snippet(lines, start_line, value),
                        engine=Engine.regex,
                        cwe=list(detector.cwe),
                        fix_suggestion=detector.fix,
                        references=list(detector.references),
                        fingerprint=fingerprint,
                    )
                )

        return findings
