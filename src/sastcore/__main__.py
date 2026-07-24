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


def main() -> None:
    gc.disable()
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
