"""Catálogo de detectores de secretos.

Cada :class:`SecretDetector` combina una expresión regular con, opcionalmente, un
umbral de entropía y/o un validador de formato. **No hay verificación activa por
red** (decisión de producto: cero telemetría durante el escaneo); la validación es
puramente estructural.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from sastcore.findings.model import Confidence, Severity

_CWE_HARDCODED_CREDS = "CWE-798"
_CWE_HARDCODED_KEY = "CWE-321"
_CWE_CLEARTEXT = "CWE-312"

_REF_CWE798 = "https://cwe.mitre.org/data/definitions/798.html"
_REF_CWE321 = "https://cwe.mitre.org/data/definitions/321.html"
_REF_CWE312 = "https://cwe.mitre.org/data/definitions/312.html"


@dataclass(frozen=True)
class SecretDetector:
    """Un detector de secretos concreto."""

    rule_id: str
    description: str
    regex: re.Pattern[str]
    severity: Severity
    confidence: Confidence
    cwe: tuple[str, ...]
    group: int = 0
    """Grupo de la regex que contiene el valor sensible (0 = match completo)."""
    min_entropy: float | None = None
    """Si se define, el valor debe superar esta entropía para reportarse."""
    validate: Callable[[str], bool] | None = None
    """Validador de formato adicional sobre el valor capturado."""
    references: tuple[str, ...] = field(default_factory=tuple)


def _looks_like_jwt(value: str) -> bool:
    """Valida que el primer segmento de un supuesto JWT sea una cabecera JSON válida."""
    header_segment = value.split(".", 1)[0]
    padding = "=" * (-len(header_segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(header_segment + padding)
        payload = json.loads(decoded)
    except (binascii.Error, ValueError):
        return False
    return isinstance(payload, dict) and ("alg" in payload or "typ" in payload)


DETECTORS: tuple[SecretDetector, ...] = (
    SecretDetector(
        rule_id="secrets.aws.access-key-id",
        description="Clave de acceso de AWS (Access Key ID) hardcodeada.",
        regex=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe=(_CWE_HARDCODED_CREDS,),
        references=(_REF_CWE798,),
    ),
    SecretDetector(
        rule_id="secrets.aws.secret-access-key",
        description="Posible AWS Secret Access Key hardcodeada junto a contexto 'aws'.",
        regex=re.compile(r"(?i)aws.{0,40}?['\"]([A-Za-z0-9/+=]{40})['\"]"),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=(_CWE_HARDCODED_CREDS,),
        group=1,
        min_entropy=3.5,
        references=(_REF_CWE798,),
    ),
    SecretDetector(
        rule_id="secrets.github.token",
        description="Token de acceso de GitHub hardcodeado.",
        regex=re.compile(r"\b(?:gh[oprsu]_[A-Za-z0-9]{36}|github_pat_[0-9A-Za-z_]{82})\b"),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe=(_CWE_HARDCODED_CREDS,),
        references=(_REF_CWE798,),
    ),
    SecretDetector(
        rule_id="secrets.google.api-key",
        description="Clave de API de Google hardcodeada.",
        regex=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=(_CWE_HARDCODED_CREDS,),
        references=(_REF_CWE798,),
    ),
    SecretDetector(
        rule_id="secrets.slack.token",
        description="Token de Slack hardcodeado.",
        regex=re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=(_CWE_HARDCODED_CREDS,),
        references=(_REF_CWE798,),
    ),
    SecretDetector(
        rule_id="secrets.private-key.pem",
        description="Clave privada en formato PEM embebida en el código.",
        regex=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=(_CWE_HARDCODED_KEY,),
        references=(_REF_CWE321,),
    ),
    SecretDetector(
        rule_id="secrets.jwt",
        description="JSON Web Token embebido en el código (revisar si es sensible).",
        regex=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        cwe=(_CWE_CLEARTEXT,),
        validate=_looks_like_jwt,
        references=(_REF_CWE312,),
    ),
    SecretDetector(
        rule_id="secrets.db.connection-string",
        description="Cadena de conexión con contraseña hardcodeada.",
        regex=re.compile(
            r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?)://"
            r"[^\s:@/]+:([^\s@/]{3,})@"
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=(_CWE_HARDCODED_CREDS,),
        group=1,
        references=(_REF_CWE798,),
    ),
    SecretDetector(
        rule_id="secrets.generic.high-entropy-assignment",
        description="Asignación de un valor de alta entropía a una variable sensible.",
        regex=re.compile(
            r"(?i)(?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*"
            r"['\"]([^'\"]{12,})['\"]"
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        cwe=(_CWE_HARDCODED_CREDS,),
        group=1,
        min_entropy=3.2,
        references=(_REF_CWE798,),
    ),
)
