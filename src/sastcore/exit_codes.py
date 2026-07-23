"""Códigos de salida del CLI.

Contrato estable para integraciones de CI/CD: cualquier script externo puede
depender de estos valores. No reordenar ni reasignar.
"""

from enum import IntEnum


class ExitCode(IntEnum):
    """Resultado de una ejecución de sastcore."""

    OK = 0
    """Sin hallazgos, o todos por debajo del umbral de ``--fail-on``."""

    FINDINGS = 1
    """Hallazgos por encima del umbral de severidad configurado."""

    ERROR = 2
    """Fallo de ejecución (configuración inválida, error interno, etc.)."""
