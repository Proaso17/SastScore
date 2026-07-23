# Arquitectura de sastcore

Documento vivo. Se amplía al final de cada fase. Las decisiones concretas viven como
ADRs numerados en [`adr/`](adr/); aquí va la visión general y las **limitaciones
conocidas** (la honestidad sobre lo que no se detecta es una feature).

## Visión general

sastcore analiza código fuente en tres pasadas independientes que producen un flujo
único de hallazgos normalizados:

```
descubrimiento de ficheros
        │
        ▼
   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
   │  pasada     │   │  pasada     │   │  pasada     │
   │  regex      │   │  patrones   │   │  taint      │
   │ (secretos)  │   │ (AST)       │   │ (flujo)     │
   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
          └─────────────────┼─────────────────┘
                            ▼
                 findings normalizados (Finding)
                            ▼
              dedup · fingerprint · baseline
                            ▼
        reporters (console · json · sarif · html · md · junit)
```

El objeto `Finding` es el centro de gravedad: todos los reporters y el modo baseline
dependen de él, por eso se diseña contra el esquema **SARIF 2.1.0** desde el inicio
(los `DataFlowStep` mapean 1:1 a `threadFlowLocation`).

## Decisiones de arquitectura (ADRs)

| ADR | Decisión | Estado |
|-----|----------|--------|
| [0000](adr/0000-usar-adrs.md) | Registrar decisiones como ADRs | Aceptado |
| [0001](adr/0001-representacion-ast.md) | Representación AST híbrida (CST↔CST + IR estrecha para taint) | Aceptado |
| [0002](adr/0002-identidad-y-fingerprint.md) | Identidad de hallazgo estilo SARIF `partialFingerprints` | Aceptado |
| [0003](adr/0003-precision-del-taint.md) | Taint flow-sensitive, path-insensitive | Aceptado |

## Requisitos no funcionales (objetivos)

- **Rendimiento:** 100k LOC en <60 s con 4 cores; paralelización por fichero, cache por
  hash de contenido (medir antes de asumir que `multiprocessing` ayuda: el parseo de
  tree-sitter es C, la contención de GIL está en el matching/propagación en Python).
- **Determinismo:** misma entrada → misma salida, ordenada por `(path, línea, rule_id)`.
- **Sin telemetría:** cero llamadas de red durante el escaneo.
- **Robustez:** un fichero que no parsea se registra a nivel debug y no tumba el escaneo.

## Limitaciones conocidas

Se irán rellenando conforme se implementen las fases.

Pasada de secretos (Fase 1):

- **Sin verificación activa por red**: la validación es puramente estructural (formato +
  entropía). No se comprueba si un secreto está vivo (respeta el NFR de cero red).
- **`.gitignore` solo en la raíz**: los ficheros de ignore anidados en subdirectorios
  todavía no se combinan.
- **Doble reporte ocasional**: un secreto con nombre de variable sensible (p. ej.
  `GITHUB_TOKEN`) puede dispararse a la vez por su detector específico y por el genérico
  de alta entropía. El genérico es de confianza baja por diseño.

Taint (Fase 4, por ADR-0003):

- Taint **path-insensitive**: no se razona sobre las condiciones de las ramas. Un
  sanitizer solo limpia el taint si **domina** el sink en el CFG.
- **Field-sensitivity superficial** (1 nivel): más allá de un nivel, el objeto se trata
  como tainted por completo.
- **Contenedores colapsados**: cualquier elemento tainted marca el contenedor entero.
- Sin análisis **interprocedural entre ficheros** en el MVP (solo intra-fichero vía
  resúmenes de función).

## Estado por fase

- **Fase 0 (completa):** esqueleto del repo, tooling (ruff + mypy strict + pytest), CI y
  CLI stub con la superficie de comandos congelada.
- **Fase 1 (completa):** discovery (walker con gitignore/sastignore, binarios, tamaño) +
  detección de lenguaje; modelo `Finding` contra SARIF, fingerprint estilo
  `partialFingerprints` y dedup; pasada de secretos (regex + entropía + validación de
  formato, sin red); reporters de consola y JSON; `scan` cableado con `--fail-on`.
