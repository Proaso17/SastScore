"""Reporter Markdown (para comentarios de PR)."""

from __future__ import annotations

from collections import Counter

from sastcore.findings.model import SEVERITY_ORDER, Finding


def _escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


class MarkdownReporter:
    """Genera un resumen Markdown con una tabla de hallazgos."""

    def render(self, findings: list[Finding], *, files_scanned: int) -> str:
        if not findings:
            return f"### sastcore\n\n✅ Sin hallazgos ({files_scanned} fichero(s) escaneado(s))."

        counts = Counter(finding.severity for finding in findings)
        breakdown = ", ".join(
            f"**{counts[sev]}** {sev.value}" for sev in SEVERITY_ORDER if counts[sev]
        )
        lines = [
            "### sastcore",
            "",
            f"{len(findings)} hallazgo(s) — {breakdown} · {files_scanned} fichero(s).",
            "",
            "| Sev | Regla | Ubicación | Mensaje |",
            "| --- | --- | --- | --- |",
        ]
        for finding in findings:
            location = f"{finding.location.path}:{finding.location.start_line}"
            lines.append(
                f"| {finding.severity.value} | `{finding.rule_id}` | "
                f"`{location}` | {_escape(finding.message)} |"
            )
        return "\n".join(lines) + "\n"
