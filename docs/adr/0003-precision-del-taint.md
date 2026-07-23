# 0003 — Precisión del taint analysis

- **Estado:** Aceptado
- **Fecha:** 2026-07-23

## Contexto

El taint analysis es la pieza que diferencia sastcore de "grep con esteroides", y también
la de mayor coste. Hay que elegir explícitamente el nivel de precisión en cuatro ejes,
equilibrando falsos positivos, recall y complejidad de implementación para un MVP.

## Decisión

| Eje | Decisión | Motivo |
|-----|----------|--------|
| **Flow-sensitivity** (orden de sentencias / def-use en el CFG) | **Sí** | Sin esto, `x = tainted; x = "safe"` da falso positivo. No negociable. |
| **Path-sensitivity** (razonar sobre condiciones de ramas) | **No** | Path-insensitive conservador. Un sanitizer solo limpia el taint si **domina** el sink en el CFG; sanitizado en una rama pero no en la otra → hallazgo. |
| **Field-sensitivity** (`req.query.a` ≠ `req.query.b`) | **Superficial (1 nivel)** | Más allá de un nivel, el objeto entero se trata como tainted. |
| **Container-sensitivity** (arrays/dicts) | **Colapsada** | Cualquier elemento tainted marca el contenedor entero (sobre-aproxima). |

Filosofía transversal: **sesgo hacia el recall**. Ante la duda, no se suprime el hallazgo;
se baja su `confidence` y se deja que el usuario filtre.

Alcance del MVP: **intraprocedural**, con salto **interprocedural dentro del mismo
fichero** vía resúmenes de función (`param N tainted → retorno tainted`). Sin
interprocedural entre ficheros.

## Consecuencias

- **A favor:** implementación abordable en un MVP; predecible; buen recall; las
  limitaciones son explicables y se documentan como features de honestidad.
- **En contra:** la insensibilidad a paths genera algún falso positivo (mitigado con
  `confidence`); la field/container-sensitivity aproximadas pueden sobre-marcar. Se
  aceptan como coste conocido y quedan registradas en `docs/architecture.md`.
