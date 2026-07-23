# 0000 — Registrar las decisiones de arquitectura como ADRs

- **Estado:** Aceptado
- **Fecha:** 2026-07-23

## Contexto

sastcore es un proyecto de largo recorrido, construido por fases y a menudo retomado en
sesiones separadas. Las decisiones de diseño no obvias (representación del AST, identidad
de los hallazgos, precisión del taint) son caras de revertir y fáciles de olvidar por qué
se tomaron.

## Decisión

Cada decisión de arquitectura no trivial se documenta como un **Architecture Decision
Record** numerado en `docs/adr/NNNN-titulo.md`, siguiendo el formato de Michael Nygard:
Contexto, Decisión, Consecuencias (y Estado). Los ADRs son inmutables una vez aceptados;
para cambiar una decisión se escribe un ADR nuevo que supersede al anterior.

## Consecuencias

- **A favor:** trazabilidad del "por qué"; onboarding y retomas en frío más rápidos.
- **En contra:** disciplina de mantenerlos al día; coste de escribir cada uno.
