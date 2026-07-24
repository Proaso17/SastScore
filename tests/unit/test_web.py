"""Tests de la aplicación web (FastAPI TestClient)."""

from __future__ import annotations

import io
import zipfile

import httpx
from fastapi.testclient import TestClient

from sastcore.web.app import app

client = TestClient(app)


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
