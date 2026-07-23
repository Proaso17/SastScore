# 0004 — Estrategia de cache

- **Estado:** Aceptado
- **Fecha:** 2026-07-23

## Contexto

Era la tercera decisión de arquitectura pendiente. El objetivo de rendimiento (100k
LOC en <60 s) y el modo diferencial de CI piden alguna forma de cache. Hay dos niveles
posibles con costes muy distintos:

1. **Cache en el run**: evitar reparsear el mismo contenido dentro de una ejecución y
   compartir el AST entre pasadas.
2. **Cache persistente cross-run**: guardar resultados en disco para re-escaneos
   incrementales (solo se reanaliza lo que cambió).

## Opciones consideradas

- Cachear el **árbol de tree-sitter** en disco: los árboles no son trivialmente
  serializables y habría que reparsear igualmente al cargar; poco valor.
- Cachear los **hallazgos** por hash de contenido: es lo que da valor real en CI
  (saltarse ficheros sin cambios), pero introduce invalidación, staleness y
  re-estampado del `path` (el fingerprint es independiente del path, pero el
  `location.path` hay que re-escribirlo al reusar).

## Decisión

- **Fase 2 — cache en el run (implementada):** `parsing/cache.py` (`ParseCache`)
  memoiza el parseo por `(lenguaje, sha256(contenido))`. Cada fichero se parsea una vez
  y el AST se comparte entre pasadas.
- **Cache persistente cross-run — diferida a la Fase 5:** clave =
  `sha256(contenido) + versión de la herramienta + hash del rulepack`, almacenada en
  `.sastcore-cache/` como JSON; al reusar, se re-estampa `location.path`. Se implementa
  junto al baseline, donde su valor (re-escaneos incrementales en CI) es máximo.

## Consecuencias

- **A favor:** la Fase 2 se centra en el motor, no en infraestructura de cache; el
  parse-once ya elimina el reparseo redundante; la cache persistente llega cuando de
  verdad se aprovecha.
- **En contra:** hasta la Fase 5 no hay aceleración de re-escaneos entre invocaciones;
  la invalidación por `versión + hash de reglas` habrá que documentarla y probarla bien.
