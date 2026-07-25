"""Punto de entrada de la CLI (``python -m sastcore`` y el script ``sastcore``).

Envuelve la app de Typer para salir con ``os._exit``: el binding de tree-sitter crashea
al recolectar sus objetos (ciclos irrompibles) durante el teardown del intérprete, así
que se omite ese teardown una vez producida la salida. El GC cíclico se desactiva por el
mismo motivo (ver ``parsing/ast.py`` y ``docs/adr``).
"""

from __future__ import annotations

import gc
import os
import sys

from sastcore.cli import app
from sastcore.exit_codes import ExitCode


def _force_utf8_stdio() -> None:
    """Emite siempre UTF-8 por stdout/stderr.

    En Windows el locale por defecto es cp1252; sin esto, la salida con acentos
    (mensajes, informes JSON/SARIF) se corrompe al redirigirla o al capturarla
    desde otro proceso (mojibake tipo "criptogrÃ¡ficamente").
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    gc.disable()
    _force_utf8_stdio()
    code: int = ExitCode.ERROR
    try:
        app()
        code = ExitCode.OK
    except SystemExit as exc:
        if exc.code is None:
            code = ExitCode.OK
        elif isinstance(exc.code, int):
            code = exc.code
        else:
            code = ExitCode.ERROR
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


if __name__ == "__main__":
    main()
