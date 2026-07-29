"""Reporter SARIF 2.1.0.

Las trazas de taint (``data_flow``) se emiten como ``codeFlows``/``threadFlows`` y el
fingerprint como ``partialFingerprints`` (para el matching de GitHub Code Scanning).
"""

from __future__ import annotations

import json
from typing import Any

from sastcore import __version__
from sastcore.findings.model import DataFlowStep, Finding, Location, Severity

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/Proaso17/SastScore"
_FINGERPRINT_KEY = "sastcore/v1"

_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# security-severity numérica (0-10) que GitHub usa para ordenar.
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


class SARIFReporter:
    """Serializa los hallazgos a SARIF 2.1.0."""

    def render(self, findings: list[Finding], *, files_scanned: int) -> str:
        rules: list[dict[str, Any]] = []
        rule_index: dict[str, int] = {}
        for finding in findings:
            if finding.rule_id not in rule_index:
                rule_index[finding.rule_id] = len(rules)
                rules.append(self._rule(finding))

        results = [self._result(finding, rule_index[finding.rule_id]) for finding in findings]

        log: dict[str, Any] = {
            "$schema": _SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "sastcore",
                            "version": __version__,
                            "informationUri": _INFO_URI,
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(log, indent=2, ensure_ascii=False)

    def _rule(self, finding: Finding) -> dict[str, Any]:
        tags = ["security", *finding.cwe]
        if finding.owasp is not None:
            tags.append(finding.owasp)
        rule: dict[str, Any] = {
            "id": finding.rule_id,
            "name": finding.rule_id,
            "shortDescription": {"text": finding.message},
            "properties": {
                "tags": tags,
                "security-severity": _SECURITY_SEVERITY[finding.severity],
            },
        }
        if finding.references:
            rule["helpUri"] = finding.references[0]
        return rule

    def _result(self, finding: Finding, rule_index: int) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index,
            "level": _LEVEL[finding.severity],
            "message": {"text": finding.message},
            "locations": [{"physicalLocation": self._physical(finding.location, finding.snippet)}],
            "partialFingerprints": {_FINGERPRINT_KEY: finding.fingerprint},
        }
        if finding.data_flow:
            result["codeFlows"] = [
                {"threadFlows": [{"locations": [self._thread_step(s) for s in finding.data_flow]}]}
            ]
        return result

    def _physical(self, location: Location, snippet: str | None = None) -> dict[str, Any]:
        region: dict[str, Any] = {
            "startLine": location.start_line,
            "startColumn": location.start_col + 1,
            "endLine": location.end_line,
            "endColumn": location.end_col + 1,
        }
        if snippet:
            region["snippet"] = {"text": snippet}
        return {"artifactLocation": {"uri": location.path}, "region": region}

    def _thread_step(self, step: DataFlowStep) -> dict[str, Any]:
        return {
            "location": {
                "physicalLocation": self._physical(step.location),
                "message": {"text": step.message},
            }
        }
