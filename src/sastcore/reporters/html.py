"""Reporter HTML autocontenido (CSS inline, sin recursos externos)."""

from __future__ import annotations

from html import escape

from sastcore import __version__
from sastcore.findings.model import Finding

_STYLE = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;
background:#0f1117;color:#e6e6e6}
header{padding:20px 28px;border-bottom:1px solid #2a2f3a}
h1{margin:0;font-size:20px}
.sub{color:#9aa4b2;font-size:13px;margin-top:4px}
main{padding:20px 28px;max-width:1000px}
.f{border:1px solid #2a2f3a;border-radius:8px;margin-bottom:14px;overflow:hidden}
.f-h{display:flex;gap:10px;align-items:center;padding:10px 14px;background:#161a22}
.badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;color:#fff}
.CRITICAL{background:#b91c1c}
.HIGH{background:#dc2626}
.MEDIUM{background:#d97706}
.LOW{background:#0891b2}
.INFO{background:#64748b}
.rid{font-family:ui-monospace,monospace;font-size:13px;color:#c9d1d9}
.loc{margin-left:auto;color:#9aa4b2;font-size:12px;font-family:ui-monospace,monospace}
.f-b{padding:10px 14px}
.msg{margin:0 0 8px}
pre{background:#0b0e14;border:1px solid #2a2f3a;border-radius:6px;padding:10px;
overflow-x:auto;font-size:12px;margin:6px 0}
.flow{list-style:none;padding-left:0;margin:8px 0 0;border-left:2px solid #2a2f3a}
.flow li{padding:2px 0 2px 12px;font-size:12px;color:#9aa4b2}
.flow code{color:#c9d1d9}
.none{color:#3fb950;font-size:15px}
"""


class HTMLReporter:
    """Genera un informe HTML autocontenido."""

    def render(self, findings: list[Finding], *, files_scanned: int) -> str:
        body = self._body(findings, files_scanned)
        return (
            "<!doctype html><html lang='es'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>sastcore — informe</title><style>{_STYLE}</style></head><body>"
            f"<header><h1>sastcore</h1><div class='sub'>v{escape(__version__)} · "
            f"{len(findings)} hallazgo(s) · {files_scanned} fichero(s)</div></header>"
            f"<main>{body}</main></body></html>"
        )

    def _body(self, findings: list[Finding], files_scanned: int) -> str:
        if not findings:
            return "<p class='none'>✓ Sin hallazgos.</p>"
        return "".join(self._card(f) for f in findings)

    def _card(self, f: Finding) -> str:
        parts = [
            "<div class='f'><div class='f-h'>",
            f"<span class='badge {f.severity.value}'>{f.severity.value}</span>",
            f"<span class='rid'>{escape(f.rule_id)}</span>",
            f"<span class='loc'>{escape(f.location.path)}:{f.location.start_line}</span>",
            "</div><div class='f-b'>",
            f"<p class='msg'>{escape(f.message)}</p>",
            f"<pre>{escape(f.snippet)}</pre>",
        ]
        if f.data_flow:
            steps = "".join(
                f"<li><code>{escape(s.location.path)}:{s.location.start_line}</code> "
                f"— {escape(s.message)}</li>"
                for s in f.data_flow
            )
            parts.append(f"<ul class='flow'>{steps}</ul>")
        if f.fix_suggestion:
            parts.append(f"<p class='msg'>💡 {escape(f.fix_suggestion)}</p>")
        parts.append("</div></div>")
        return "".join(parts)
