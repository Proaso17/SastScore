# 0005 — Workaround del ciclo de vida / GC de tree-sitter

- **Estado:** Aceptado
- **Fecha:** 2026-07-24

## Contexto

Al integrar el taint analysis (Fase 4), que hace un uso intensivo del parseo y crea
muchos objetos, aparecieron **segfaults** (access violation, `0xC0000005`) no
deterministas. La depuración (ver `docs/` y el historial) identificó **dos** causas, ambas
en extensiones nativas, específicas de esta plataforma (Windows + CPython 3.12):

1. **tree-sitter (binding 0.26):** sus objetos `Tree`/`Node` forman ciclos de referencias
   irrompibles. Cuando el **GC cíclico** los escanea (`tp_traverse`) o los recolecta, el
   binding hace un acceso a memoria inválido → crash. Ocurre tanto a mitad de una travesía
   como al acumularse entre parseos o en el teardown del intérprete.
2. **pydantic-core:** crear y **liberar** cientos de miles de modelos pydantic
   (`Location`/`DataFlowStep`, que el taint generaba por asignación × función × fixpoint)
   corrompía la memoria al desalojarlos.

## Decisión

- **Materializar el árbol:** en `parsing/ast.py`, el árbol de tree-sitter se copia a
  `Node` inmutables de Python (dataclass con slots) en el parseo y el `Tree` se descarta.
  El resto del motor no toca nunca un nodo de tree-sitter. La recolección es iterativa
  (no recursiva, para no desbordar el C-stack) vía `.children`, con registros que son
  **tuplas de primitivos** (no rastreadas por el GC).
- **Desactivar el GC cíclico al parsear** (`gc.disable()` en `parse`): el GC nunca escanea
  ni recolecta objetos de tree-sitter. Los objetos transitorios se abandonan; su cantidad
  está **acotada por fichero** y el SO recupera la memoria al terminar el proceso.
- **Salir con `os._exit`:** el CLI (`__main__.main`) y la suite de tests
  (`pytest_sessionfinish`) terminan con `os._exit` tras vaciar la salida, para saltarse la
  recolección del teardown del intérprete (que también crashea).
- **`Location`/`DataFlowStep` son dataclasses**, no modelos pydantic, para evitar el bug
  de desalojo en masa. `Finding` sigue siendo pydantic (se crean pocos) y las serializa.
- **Los resúmenes de función no construyen traza** (`track_trace=False`): no la necesitan
  y así se evita crear millones de objetos.

## Consecuencias

- **A favor:** el motor completo (162 tests) corre de forma estable en esta plataforma; el
  CLI produce la traza `data_flow` correcta y sale con el código adecuado.
- **En contra:** el GC cíclico queda desactivado durante una ejecución (los ciclos de
  *nuestro* código —escasos— también se abandonan hasta la salida); hay una fuga acotada
  de objetos de tree-sitter por proceso; `os._exit` omite los handlers `atexit` (por eso se
  vacía la salida antes). Es una herramienta de ejecución corta (escanear y salir), así que
  el coste es asumible.
- **Alternativa futura:** los paquetes oficiales individuales (`tree-sitter-python`, …) o
  una versión distinta del binding podrían no tener el bug; migrar permitiría reactivar el
  GC. tree-sitter 0.23 se probó pero tiene una API incompatible.
