"""Tests de la aplicación web (FastAPI TestClient)."""

from __future__ import annotations

import io
import json
import subprocess
import tarfile
import zipfile
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

import sastcore.web.app as app_mod
import sastcore.web.scanning as scanning
from sastcore.web.app import app
from sastcore.web.reports_store import FilesystemReportStore
from sastcore.web.scanning import ScanReport

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_rate_limit() -> None:
    """Cada test parte con el rate-limit a cero.

    Todos los tests comparten la IP del TestClient, así que sin esto los últimos
    del fichero recibirían 429 al agotarse la cuota acumulada.
    """
    app_mod._rate_hits.clear()


def _zip(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _post_zip(files: dict[str, str], route: str = "/api/scan") -> httpx.Response:
    data = _zip(files)
    response: httpx.Response = client.post(
        route, files={"files": ("repo.zip", data, "application/zip")}
    )
    return response


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_index_page() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "Analizar" in response.text


def test_api_scan_detects_pattern_vulnerability() -> None:
    response = _post_zip({"app.py": "import os\nos.system(cmd)\n"})
    assert response.status_code == 200
    ids = [f["rule_id"] for f in response.json()["findings"]]
    assert "py.dangerous.os-system" in ids


def test_api_scan_detects_taint_flow() -> None:
    code = "def v(request, cursor):\n    q = request.args.get('id')\n    cursor.execute(q)\n"
    response = _post_zip({"views.py": code})
    ids = [f["rule_id"] for f in response.json()["findings"]]
    assert "py.taint.sql-injection" in ids


def test_scan_html_results_page() -> None:
    response = _post_zip({"app.py": "eval(userInput)\n"}, route="/scan")
    assert response.status_code == 200
    assert "py.dangerous.eval" in response.text


def test_individual_file_upload() -> None:
    response = client.post(
        "/api/scan", files={"files": ("x.py", b"import os\nos.system(x)\n", "text/x-python")}
    )
    ids = [f["rule_id"] for f in response.json()["findings"]]
    assert "py.dangerous.os-system" in ids


def test_zip_slip_is_rejected() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../evil.py", "x = 1\n")
    response = client.post(
        "/api/scan", files={"files": ("bad.zip", buffer.getvalue(), "application/zip")}
    )
    assert response.status_code == 400
    assert "error" in response.json()


def test_clean_code_has_no_findings() -> None:
    response = _post_zip({"ok.py": "def add(a, b):\n    return a + b\n"})
    assert response.status_code == 200
    assert response.json()["findings"] == []


def test_api_scan_preserves_accents() -> None:
    """Los acentos del subproceso deben llegar intactos (sin mojibake cp1252)."""
    response = _post_zip({"c.py": "import hashlib\nh = hashlib.md5(b'x')\n"})
    assert response.status_code == 200
    findings = response.json()["findings"]
    finding = next(f for f in findings if f["rule_id"] == "py.crypto.weak-hash-md5")
    blob = finding["message"] + (finding.get("fix_suggestion") or "")
    assert "criptográficamente" in blob
    assert "contraseñas" in blob
    assert "Ã" not in blob and "Â" not in blob  # sin mojibake


def test_scan_html_results_page_preserves_accents() -> None:
    response = _post_zip({"c.py": "import hashlib\nh = hashlib.md5(b'x')\n"}, route="/scan")
    assert response.status_code == 200
    assert "criptográficamente" in response.text
    assert "Ã" not in response.text


def test_security_headers_present() -> None:
    response = client.get("/")
    csp = response.headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_interactive_docs_disabled() -> None:
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_legal_page() -> None:
    response = client.get("/legal")
    assert response.status_code == 200
    body = response.text.lower()
    assert "privacidad" in body
    assert "no se ejecuta" in body
    assert "no se almacena" in body
    assert "migonagu@gmail.com" in response.text


def test_footer_has_contact_and_legal_link() -> None:
    body = client.get("/").text
    assert 'href="/legal"' in body
    assert "migonagu@gmail.com" in body


def test_request_id_header() -> None:
    generated = client.get("/health")
    assert generated.headers.get("x-request-id")
    propagated = client.get("/health", headers={"X-Request-ID": "trace-abc-123"})
    assert propagated.headers["x-request-id"] == "trace-abc-123"


def test_report_downloads_all_formats() -> None:
    payload = _post_zip({"c.py": "import hashlib\nh = hashlib.md5(b'x')\n"}).json()
    for fmt, ext in {
        "sarif": ".sarif",
        "json": ".json",
        "markdown": ".md",
        "html": ".html",
    }.items():
        response = client.post(f"/report/{fmt}", json=payload)
        assert response.status_code == 200, fmt
        disposition = response.headers["content-disposition"]
        assert "attachment" in disposition
        assert ext in disposition
        assert "py.crypto.weak-hash-md5" in response.text


def test_report_html_escapes_content() -> None:
    payload = _post_zip({"c.py": "import hashlib\nh = hashlib.md5(b'x')\n"}).json()
    payload["findings"][0]["message"] = "<script>alert(1)</script>"
    response = client.post("/report/html", json=payload)
    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_report_unknown_format_rejected() -> None:
    response = client.post("/report/pdf", json={"files_scanned": 0, "findings": []})
    assert response.status_code == 400


def test_report_invalid_findings_rejected() -> None:
    response = client.post("/report/json", json={"files_scanned": 0, "findings": [{"nope": 1}]})
    assert response.status_code == 400


def _make_tar(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def test_parse_github_url_valid() -> None:
    assert scanning.parse_github_url("https://github.com/octocat/Hello-World") == (
        "octocat",
        "Hello-World",
    )
    assert scanning.parse_github_url("https://github.com/owner/repo.git") == ("owner", "repo")
    assert scanning.parse_github_url("https://github.com/o/r/tree/main") == ("o", "r")


def test_parse_github_url_rejects_non_github() -> None:
    for bad in ("http://github.com/a/b", "https://evil.com/a/b", "https://github.com/only", "nope"):
        with pytest.raises(scanning.UploadError):
            scanning.parse_github_url(bad)


def test_extract_tarball_rejects_path_traversal(tmp_path: Path) -> None:
    data = _make_tar({"../evil.py": b"x = 1\n"})
    with pytest.raises(scanning.UploadError):
        scanning.extract_tarball(data, tmp_path)


def test_scan_url_scans_downloaded_repo(monkeypatch: pytest.MonkeyPatch) -> None:
    tar = _make_tar({"repo-main/app.py": b"import os\nos.system(cmd)\n"})
    monkeypatch.setattr(scanning, "download_github_tarball", lambda owner, repo: tar)
    response = client.post("/api/scan-url", json={"url": "https://github.com/octocat/repo"})
    assert response.status_code == 200
    ids = [f["rule_id"] for f in response.json()["findings"]]
    assert "py.dangerous.os-system" in ids


def test_scan_url_rejects_non_github() -> None:
    response = client.post("/api/scan-url", json={"url": "https://evil.example.com/a/b"})
    assert response.status_code == 400
    assert "error" in response.json()


# ── Informes compartibles ───────────────────────────────────────────────────
_FINDING = {
    "rule_id": "py.dangerous.eval",
    "message": "Uso de eval",
    "severity": "HIGH",
    "confidence": "HIGH",
    "location": {
        "path": "a.py",
        "start_line": 1,
        "end_line": 1,
        "start_col": 0,
        "end_col": 7,
    },
    "snippet": "eval(x)",
    "engine": "pattern",
}


def _use_tmp_store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(app_mod, "report_store", FilesystemReportStore(tmp_path, 3600))


def test_share_and_view_report(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_tmp_store(monkeypatch, tmp_path)
    created = client.post("/api/share", json={"files_scanned": 1, "findings": [_FINDING]})
    assert created.status_code == 200
    body = created.json()
    assert body["url"] == f"/r/{body['id']}"

    viewed = client.get(body["url"])
    assert viewed.status_code == 200
    assert "py.dangerous.eval" in viewed.text
    assert "Informe compartido" in viewed.text


def test_shared_report_expires(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Un informe con TTL agotado deja de servirse (y responde 404)."""
    monkeypatch.setattr(app_mod, "report_store", FilesystemReportStore(tmp_path, -1))
    created = client.post("/api/share", json={"files_scanned": 1, "findings": [_FINDING]})
    report_id = created.json()["id"]
    expired = client.get(f"/r/{report_id}")
    assert expired.status_code == 404
    assert "ya no está disponible" in expired.text


def test_unknown_report_id_returns_404(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_tmp_store(monkeypatch, tmp_path)
    assert client.get("/r/noexisteeste").status_code == 404


def test_report_id_traversal_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Un id con caracteres fuera de la lista blanca no toca el sistema de ficheros."""
    store = FilesystemReportStore(tmp_path, 3600)
    assert store.load("../../etc/passwd") is None
    assert store.load("bad id!") is None


def test_share_rejects_invalid_findings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_tmp_store(monkeypatch, tmp_path)
    response = client.post("/api/share", json={"files_scanned": 0, "findings": [{"nope": 1}]})
    assert response.status_code == 400


def test_rate_limiter_trips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_mod, "RATE_LIMIT_PER_MIN", 3)
    app_mod._rate_hits.clear()
    ip = "203.0.113.7"
    assert [app_mod._rate_limited(ip) for _ in range(3)] == [False, False, False]
    assert app_mod._rate_limited(ip) is True
    app_mod._rate_hits.clear()


def test_scan_rate_limit_returns_429(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_mod, "RATE_LIMIT_PER_MIN", 1)
    monkeypatch.setattr(
        app_mod, "prepare_and_scan", lambda uploads: ScanReport(files_scanned=0, findings=[])
    )
    app_mod._rate_hits.clear()
    payload = {"files": ("a.py", b"x = 1\n", "text/x-python")}
    assert client.post("/api/scan", files=payload).status_code == 200
    blocked = client.post("/api/scan", files=payload)
    assert blocked.status_code == 429
    assert "error" in blocked.json()
    app_mod._rate_hits.clear()


def test_client_ip_resists_xff_spoofing() -> None:
    # El cliente falsifica la primera IP; el proxy de confianza añade la real por
    # la derecha. Con 1 salto de confianza (Cloud Run) debemos coger la última.
    assert app_mod._pick_client_ip("1.2.3.4, 203.0.113.9", "10.0.0.1") == "203.0.113.9"
    assert app_mod._pick_client_ip(None, "10.0.0.1") == "10.0.0.1"
    assert app_mod._pick_client_ip("  ", "10.0.0.1") == "10.0.0.1"


def test_too_many_files_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_mod, "MAX_FILES", 3)
    files = [("files", (f"f{i}.py", b"x = 1\n", "text/x-python")) for i in range(5)]
    response = client.post("/api/scan", files=files)
    assert response.status_code == 400
    assert "error" in response.json()


def test_oversized_content_length_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_mod, "MAX_UPLOAD_BYTES", 10)
    response = client.post("/api/scan", files={"files": ("a.py", b"x = 1\n" * 50, "text/x-python")})
    assert response.status_code == 413
    assert "error" in response.json()


def _scannable(tmp_path: Path) -> Path:
    """Directorio con un fichero analizable (scan_directory descubre antes de lanzar)."""
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    return tmp_path


def test_scan_timeout_becomes_upload_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def _timeout(*args: object, **kwargs: object) -> object:
        raise subprocess.TimeoutExpired(cmd="sastcore", timeout=1)

    monkeypatch.setattr(subprocess, "run", _timeout)
    with pytest.raises(scanning.UploadError):
        scanning.scan_directory(_scannable(tmp_path))


def test_scan_error_does_not_leak_stderr(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def _fail(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["sastcore"], returncode=2, stdout="", stderr="/srv/secret/internal.py Traceback"
        )

    monkeypatch.setattr(subprocess, "run", _fail)
    with pytest.raises(scanning.UploadError) as excinfo:
        scanning.scan_directory(_scannable(tmp_path))
    message = str(excinfo.value)
    assert "secret" not in message
    assert "Traceback" not in message


_SEGFAULT_RC = 3221225477  # 0xC0000005 en Windows (access violation)


def test_complete_report_used_even_if_process_crashed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Si el informe JSON está completo, se usa aunque el proceso muriera al salir.

    El binding de tree-sitter puede provocar un fallo de segmentación al liberar
    memoria en árboles grandes (ADR-0005), después de haber emitido el informe.
    Descartarlo hacía que la web dijese "el análisis falló" en repos válidos.
    """
    report = '{"files_scanned": 68, "findings": []}'

    def _crash_after_output(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["sastcore"], returncode=_SEGFAULT_RC, stdout=report, stderr="access violation"
        )

    monkeypatch.setattr(subprocess, "run", _crash_after_output)
    result = scanning.scan_directory(_scannable(tmp_path))
    assert result.files_scanned == 68


def test_truncated_report_after_crash_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Un informe cortado a medias (crash durante el escaneo) sí debe fallar."""

    def _crash_mid_scan(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["sastcore"],
            returncode=_SEGFAULT_RC,
            stdout='{"files_scanned": 68, "findings": [{"rule_id": "x.y"',
            stderr="access violation",
        )

    monkeypatch.setattr(subprocess, "run", _crash_mid_scan)
    with pytest.raises(scanning.UploadError):
        scanning.scan_directory(_scannable(tmp_path))


def test_non_object_report_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """JSON válido pero que no es un objeto de informe tampoco se acepta."""

    def _weird(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["sastcore"], returncode=0, stdout="[1, 2, 3]", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", _weird)
    with pytest.raises(scanning.UploadError):
        scanning.scan_directory(_scannable(tmp_path))


def test_scan_splits_batch_and_skips_only_the_bad_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Un fichero que revienta el proceso no debe arruinar el resto del análisis."""
    for i in range(4):
        (tmp_path / f"f{i}.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "bad.py").write_text("y = 2\n", encoding="utf-8")

    def _crash_if_bad_included(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        targets = [arg for arg in command if arg.endswith(".py")]
        if any("bad" in target for target in targets):
            if len(targets) > 1:  # lote contaminado: muere sin informe
                return subprocess.CompletedProcess(command, _SEGFAULT_RC, "", "boom")
            return subprocess.CompletedProcess(command, _SEGFAULT_RC, "", "boom")
        report = f'{{"files_scanned": {len(targets)}, "findings": []}}'
        return subprocess.CompletedProcess(command, 0, report, "")

    monkeypatch.setattr(subprocess, "run", _crash_if_bad_included)
    monkeypatch.setattr(scanning, "SCAN_BATCH_FILES", 5)
    result = scanning.scan_directory(tmp_path)
    # Los 4 ficheros buenos se analizan; solo se omite el problemático.
    assert result.files_scanned == 4


def test_scan_merges_results_across_batches(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Con varios lotes, los hallazgos y el recuento se suman."""
    for i in range(6):
        (tmp_path / f"f{i}.py").write_text("x = 1\n", encoding="utf-8")

    def _one_finding_per_batch(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        targets = [arg for arg in command if arg.endswith(".py")]
        finding = dict(_FINDING)
        report = json.dumps({"files_scanned": len(targets), "findings": [finding]})
        return subprocess.CompletedProcess(command, 1, report, "")

    monkeypatch.setattr(subprocess, "run", _one_finding_per_batch)
    monkeypatch.setattr(scanning, "SCAN_BATCH_FILES", 2)
    result = scanning.scan_directory(tmp_path)
    assert result.files_scanned == 6
    assert len(result.findings) == 3  # 6 ficheros / lotes de 2 = 3 lotes


def test_logs_go_to_stderr() -> None:
    import logging
    import sys

    from rich.logging import RichHandler

    import sastcore._logging as logging_module

    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_configured = logging_module._configured
    root.handlers.clear()
    logging_module._configured = False
    try:
        logging_module.configure_logging()
        handler = root.handlers[0]
        assert isinstance(handler, RichHandler)
        assert handler.console.file is sys.stderr
    finally:
        root.handlers[:] = saved_handlers
        logging_module._configured = saved_configured
