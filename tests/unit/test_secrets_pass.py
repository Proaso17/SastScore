"""Tests unitarios de la pasada de secretos."""

from __future__ import annotations

from sastcore.engine.secrets.pass_ import SecretsPass


def _rule_ids(content: str, rel_path: str = "a.py") -> set[str]:
    findings = SecretsPass().scan_file(rel_path=rel_path, content=content)
    return {f.rule_id for f in findings}


def test_detects_aws_access_key() -> None:
    assert "secrets.aws.access-key-id" in _rule_ids('key = "AKIAIOSFODNN7EXAMPLE"\n')


def test_detects_aws_secret_key_with_context() -> None:
    secret = "AbCdEf012345/GhIjKl678901+MnOpQr234567=="
    assert "secrets.aws.secret-access-key" in _rule_ids(f'aws_secret = "{secret}"\n')


def test_detects_github_token() -> None:
    token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    assert "secrets.github.token" in _rule_ids(f'const t = "{token}";\n', "a.js")


def test_detects_private_key_pem() -> None:
    content = "-----BEGIN RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----\n"
    assert "secrets.private-key.pem" in _rule_ids(content)


def test_detects_connection_string() -> None:
    content = 'url = "postgres://admin:sup3rS3cret@db.example.com:5432/app"\n'
    assert "secrets.db.connection-string" in _rule_ids(content)


def test_masks_secret_in_snippet() -> None:
    findings = SecretsPass().scan_file(rel_path="a.py", content='k = "AKIAIOSFODNN7EXAMPLE"\n')
    finding = next(f for f in findings if f.rule_id == "secrets.aws.access-key-id")
    assert "AKIAIOSFODNN7EXAMPLE" not in finding.snippet
    assert "AKIA" in finding.snippet  # se conserva un prefijo enmascarado


def test_secret_value_never_stored_in_finding() -> None:
    findings = SecretsPass().scan_file(rel_path="a.py", content='k = "AKIAIOSFODNN7EXAMPLE"\n')
    finding = next(f for f in findings if f.rule_id == "secrets.aws.access-key-id")
    dumped = finding.model_dump_json()
    assert "AKIAIOSFODNN7EXAMPLE" not in dumped


def test_low_entropy_generic_is_ignored() -> None:
    # Valor largo pero de baja entropía: no debe dispararse el detector genérico.
    assert "secrets.generic.high-entropy-assignment" not in _rule_ids('password = "aaaaaaaaaaaa"\n')


def test_high_entropy_generic_is_flagged() -> None:
    content = 'api_key = "8f14e45fceea167a5a36dedd4bea2543"\n'
    assert "secrets.generic.high-entropy-assignment" in _rule_ids(content)


def test_valid_jwt_flagged() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N"
    assert "secrets.jwt" in _rule_ids(f'token = "{jwt}"\n')


def test_invalid_jwt_rejected() -> None:
    fake = "eyJZZZZZZZZZZZ.aaaaaaaaaaaa.bbbbbbbbbbbb"
    assert "secrets.jwt" not in _rule_ids(f'x = "{fake}"\n')


def test_plain_code_has_no_findings() -> None:
    content = "def add(a, b):\n    return a + b\n"
    assert SecretsPass().scan_file(rel_path="a.py", content=content) == []


def test_secret_finding_has_remediation() -> None:
    findings = SecretsPass().scan_file(rel_path="a.py", content='k = "AKIAIOSFODNN7EXAMPLE"\n')
    finding = next(f for f in findings if f.rule_id == "secrets.aws.access-key-id")
    assert finding.fix_suggestion
    assert "rota" in finding.fix_suggestion.lower() or "entorno" in finding.fix_suggestion.lower()
