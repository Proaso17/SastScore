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

Se irán rellenando conforme se implementen las fases. Punto de partida (por ADR-0003):

- Taint **path-insensitive**: no se razona sobre las condiciones de las ramas. Un
  sanitizer solo limpia el taint si **domina** el sink en el CFG.
- **Field-sensitivity superficial** (1 nivel): más allá de un nivel, el objeto se trata
  como tainted por completo.
- **Contenedores colapsados**: cualquier elemento tainted marca el contenedor entero.
- Sin análisis **interprocedural entre ficheros** en el MVP (solo intra-fichero vía
  resúmenes de función).

## Estado por fase

- **Fase 0 (en curso):** esqueleto del repo, tooling (ruff + mypy strict + pytest), CI y
  CLI stub con la superficie de comandos congelada.
