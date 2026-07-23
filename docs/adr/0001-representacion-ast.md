# 0001 — Representación del AST y motor de patrones

- **Estado:** Aceptado
- **Fecha:** 2026-07-23

## Contexto

sastcore es multi-lenguaje (JS, TS, Python en el MVP) y necesita dos motores que operan
sobre el árbol sintáctico: el **motor de patrones** (matching estructural con
metavariables y elipsis) y el **taint analysis** (CFG, DFG, propagación). tree-sitter
produce un **árbol sintáctico concreto (CST)** distinto por lenguaje, con mucho ruido
sintáctico y tipos de nodo que no coinciden entre lenguajes.

## Opciones consideradas

1. **IR unificada completa:** normalizar todos los lenguajes a un AST abstracto común y
   escribir los motores una sola vez. Coste altísimo, pierde información en la
   normalización, y es scope creep para un MVP.
2. **Acoplar todo al CST de tree-sitter:** escribir motores per-lenguaje sobre el árbol
   concreto. Rápido de empezar, pero duplica lógica y dificulta reglas cross-lenguaje.
3. **Híbrido.**

## Decisión

Enfoque **híbrido**:

- **Motor de patrones — unificación CST↔CST (el truco de Semgrep):** un patrón es un
  snippet de código parametrizado; se **parsea con la misma gramática tree-sitter que el
  fichero objetivo** y se unifica árbol contra árbol en el mismo lenguaje. `$X` son
  metavariables (capturan y se pueden referenciar dentro de la regla) y `...` es elipsis.
  No hace falta IR común: el algoritmo de unificación se comparte, parametrizado por
  lenguaje.
- **Taint analysis — IR estrecha:** un modelo normalizado de ~6 conceptos (`Assign`,
  `Call`, `MemberAccess`, `Literal`, `Name` y nodos de control). Adaptadores per-lenguaje
  proyectan el CST a ese modelo; el CFG/DFG operan solo sobre él. Es una IR mínima, no un
  compilador.
- **`parsing/ast.py`** es un wrapper fino y estable sobre el nodo tree-sitter (posición,
  tipo, hijos, texto), para aislar el resto del código del parser concreto.

## Consecuencias

- **A favor:** evita construir un compilador a IR; las reglas se escriben "como código de
  ejemplo"; el motor de patrones es preciso porque razona en la sintaxis real del lenguaje.
- **En contra:** el motor de patrones es parametrizable por lenguaje (no 100% compartido);
  la IR estrecha del taint requiere un adaptador por lenguaje que hay que mantener.
- Cambiar de parser en el futuro solo obliga a reescribir el wrapper y los adaptadores, no
  los motores.
