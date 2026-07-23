"""Configuración de logging de la aplicación.

Un único punto de entrada (:func:`configure_logging`) para no reconfigurar el
logging más de una vez y mantener un formato coherente en toda la herramienta.
"""

from __future__ import annotations

import logging

from rich.logging import RichHandler

_configured = False


def configure_logging(*, verbose: bool = False, quiet: bool = False) -> None:
    """Configura el logging global una sola vez.

    Args:
        verbose: sube el nivel a ``DEBUG``.
        quiet: baja el nivel a ``ERROR`` (tiene prioridad sobre ``verbose``
            solo si ``verbose`` es ``False``).
    """
    global _configured
    if _configured:
        return

    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.ERROR
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    )
    _configured = True
