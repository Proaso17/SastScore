"""Supresión inline de hallazgos.

Formato: ``sastcore:ignore <rule_id> -- <razón>`` en la misma línea del hallazgo o en
la línea inmediatamente anterior. **La razón es obligatoria**: sin ella, se registra un
aviso y el hallazgo NO se suprime.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence

from sastcore.findings.model import Finding

logger = logging.getLogger(__name__)

_DIRECTIVE_RE = re.compile(
    r"sastcore:ignore\s+(?P<rule>[\w.\-]+)(?:\s+--\s+(?P<reason>\S.*?))?\s*$"
)


def _collect(file_lines: Sequence[str]) -> dict[int, set[str]]:
    """Mapea cada línea (1-indexada) al conjunto de rule_ids suprimidos en ella."""
    suppressed: dict[int, set[str]] = {}
    for line_number, line in enumerate(file_lines, start=1):
        match = _DIRECTIVE_RE.search(line)
        if match is None:
            continue
        if not match.group("reason"):
            logger.warning(
                "sastcore:ignore para '%s' sin razón (línea %d): se ignora la supresión.",
                match.group("rule"),
                line_number,
            )
            continue
        rule_id = match.group("rule")
        # La directiva cubre su propia línea (comentario inline) y la siguiente
        # (comentario en la línea anterior al hallazgo).
        suppressed.setdefault(line_number, set()).add(rule_id)
        suppressed.setdefault(line_number + 1, set()).add(rule_id)
    return suppressed


def apply_suppressions(findings: list[Finding], file_lines: Sequence[str]) -> list[Finding]:
    """Filtra los hallazgos suprimidos por directivas ``sastcore:ignore``."""
    suppressed = _collect(file_lines)
    return [
        finding
        for finding in findings
        if finding.rule_id not in suppressed.get(finding.location.start_line, set())
    ]
