# Escribir reglas para sastcore

Esta guía te permite añadir una regla propia sin conocer el código interno del motor.
Una regla es un fichero YAML dentro de un *rulepack*; sastcore la carga, la valida y la
aplica en cada escaneo.

## Dónde viven las reglas

Los rulepacks están en `src/sastcore/rulepacks/<lenguaje>/<fichero>.yml`, por ejemplo
`src/sastcore/rulepacks/python/crypto.yml`. Un fichero contiene una **lista** de reglas.
Al arrancar, sastcore carga todos los `*.yml` de ese árbol.

## Anatomía de una regla

```yaml
- id: py.dangerous.eval          # identificador único: <lang>.<categoria>.<nombre>
  languages: [python]            # python | javascript | typescript
  mode: pattern                  # pattern | taint
  severity: HIGH                 # CRITICAL | HIGH | MEDIUM | LOW | INFO
  confidence: MEDIUM             # HIGH | MEDIUM | LOW  (opcional, default MEDIUM)
  message: "Uso de eval(); ejecución de código arbitrario."
  cwe: ["CWE-95"]                # identificadores CWE reales
  owasp: "A03:2021-Injection"    # categoría OWASP (opcional)
  pattern: "eval($X)"            # ver más abajo
  fix_suggestion: "Evita eval(); usa una tabla de despacho."   # opcional
  references:                    # enlaces (opcional)
    - https://cwe.mitre.org/data/definitions/95.html
  tests:                         # OBLIGATORIO: fixtures bad y good
    bad:  tests/rules/fixtures/python/py.dangerous.eval_bad.py
    good: tests/rules/fixtures/python/py.dangerous.eval_good.py
```

Reglas importantes:

- El `id` debe ser único en todo el motor.
- **`tests.bad` y `tests.good` son obligatorios**: una regla sin ambos fixtures no se
  carga (el validador la rechaza). Es una garantía de calidad.
- Usa CWE/OWASP **reales y verificables**. Si no estás seguro de un CWE, déjalo vacío.
- Un campo desconocido (un typo) hace que la regla no cargue (`extra=forbid`).

## Modo `pattern`: matching estructural

Un patrón es un fragmento de código de ejemplo. El matching es **estructural** sobre el
AST, así que ignora el formato, los espacios y los comentarios, y compara los literales
string sin importar el estilo de comillas (`"x"` ≡ `'x'`).

Dos comodines:

- `$X` — **metavariable**: casa cualquier subexpresión. La misma `$X` debe casar el mismo
  texto (consistencia). Ejemplo: `eq($X, $X)` casa `eq(a, a)` pero no `eq(a, b)`.
- `...` — **elipsis**: casa cualquier secuencia de argumentos o sentencias. Ejemplo:
  `subprocess.run(..., shell=True)` casa aunque haya otros argumentos.

Para varias alternativas, usa `pattern-either` en lugar de `pattern`:

```yaml
  pattern-either:
    - "child_process.exec($X)"
    - "cp.exec($X)"
```

**Limitaciones del matcher** (tenlas en cuenta al escribir patrones):

- No distingue operadores dentro de una expresión (`a + b` y `a - b` casan igual).
- No resuelve imports ni alias: `from os import system; system(x)` no casa
  `os.system($X)`. Enumera las formas con `pattern-either` cuando importe.
- La elipsis solo funciona en listas (argumentos, sentencias), no en cualquier posición.

## Modo `taint`: flujo de datos

Una regla de taint declara de dónde vienen los datos no confiables (`sources`), qué los
limpia (`sanitizers`) y a dónde no deben llegar (`sinks`). El motor reporta un hallazgo si
un dato de un source alcanza un sink sin pasar por un sanitizer.

```yaml
- id: py.taint.sql-injection
  languages: [python]
  mode: taint
  severity: HIGH
  message: "Entrada no confiable alcanza una consulta SQL."
  cwe: ["CWE-89"]
  owasp: "A03:2021-Injection"
  sources:
    - pattern: request.args        # objeto de entrada no confiable
    - pattern: request.form
  sanitizers:
    - pattern: int($X)             # neutraliza el taint
  sinks:
    - pattern: $CUR.execute($Q, ...)
      taint_arg: 0                 # argumento (0-indexado) que se vigila
  tests:
    bad:  tests/rules/fixtures/python/py.taint.sql-injection_bad.py
    good: tests/rules/fixtures/python/py.taint.sql-injection_good.py
```

- `sources` y `sinks` son obligatorios en modo taint.
- En un sink, `taint_arg` indica qué argumento no debe recibir dato tainted.
- Usa el **objeto** de entrada como source (p. ej. `request.args`, `req.query`): así se
  cubren tanto el acceso a campos (`request.args.get("id")`) como la desestructuración.
- El análisis es intraprocedural con salto entre funciones del mismo fichero; el hallazgo
  incluye la traza source → … → sink.

## Los fixtures (bad / good)

Cada regla necesita dos ficheros de ejemplo:

- `*_bad.<ext>`: código que **debe** disparar la regla.
- `*_good.<ext>`: código equivalente y seguro que **no** debe dispararla.

Convención de nombres y ubicación:
`tests/rules/fixtures/<lenguaje>/<id-de-la-regla>_bad.<ext>` (y `_good`).

Ejemplo (`py.dangerous.eval_bad.py` y `_good.py`):

```python
# _bad.py                       # _good.py
def run(expr):                  import ast
    return eval(expr)           def run(expr):
                                    return ast.literal_eval(expr)
```

## Probar tu regla

La suite tiene un test parametrizado que recorre **todas** las reglas y verifica que cada
`bad` dispara y cada `good` queda limpio:

```bash
python -m pytest tests/unit/test_pattern_pass.py -q   # reglas de patrón
python -m pytest tests/unit/test_taint_pass.py -q     # reglas de taint
```

Comprobación rápida sobre un fichero concreto:

```bash
sastcore scan mi_fichero.py
```

## Checklist para una regla nueva

1. Elige `id`, `mode`, `severity` y CWE/OWASP reales.
2. Escribe el `pattern` (o sources/sanitizers/sinks) y el `message`.
3. Crea `*_bad` y `*_good` en `tests/rules/fixtures/<lenguaje>/`.
4. Añade la regla al `.yml` correspondiente del rulepack.
5. Ejecuta los tests parametrizados: el `bad` dispara, el `good` no.
6. Escanea un proyecto real para comprobar la tasa de falsos positivos.
