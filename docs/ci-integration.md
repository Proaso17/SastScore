# Integración en CI/CD

sastcore está pensado para CI: salida SARIF nativa, modo diferencial (baseline) y códigos
de salida estables (`0` limpio, `1` hallazgos sobre el umbral, `2` error).

## GitHub Actions

La acción `action.yml` instala sastcore y genera un SARIF. Súbelo con la acción oficial de
Code Scanning para verlo en la pestaña *Security*:

```yaml
# .github/workflows/sastcore.yml
name: sastcore
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # necesario para subir el SARIF

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: sastcore
        uses: OWNER/sastcore@v1          # o ./ si la acción está en el mismo repo
        with:
          path: "."
          output: "sastcore.sarif"
          fail-on: "HIGH"                 # opcional
      - name: Subir SARIF
        if: always()                      # sube aunque el paso anterior falle
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: "sastcore.sarif"
```

En SARIF, los flujos de taint se exportan como `codeFlows`, así que GitHub muestra el
recorrido source → … → sink paso a paso.

## Modo diferencial (baseline)

Para no bloquear un proyecto por deuda existente, fija un baseline y reporta solo lo nuevo:

```bash
# una vez, sobre el estado actual
sastcore baseline create . -o .sastcore-baseline.json

# en cada PR
sastcore scan . --baseline .sastcore-baseline.json --fail-on HIGH
```

El baseline es robusto: como el fingerprint es independiente de la línea y del nombre del
fichero, mover o renombrar código no genera falsos hallazgos nuevos.

## Pre-commit

sastcore se puede usar como hook de [pre-commit](https://pre-commit.com):

```yaml
# .pre-commit-config.yaml del proyecto consumidor
repos:
  - repo: https://github.com/OWNER/sastcore
    rev: v0.0.0
    hooks:
      - id: sastcore
        args: [--fail-on, HIGH]   # opcional, sobreescribe el default
```

## Docker

```bash
docker build -t sastcore .
docker run --rm -v "$PWD:/src" sastcore scan /src --fail-on HIGH
docker run --rm -v "$PWD:/src" sastcore scan /src -f sarif -o /src/out.sarif
```

## Configuración por fichero

`sastcore init` genera un `.sastcore.yml` con las opciones del proyecto (exclusiones,
`fail_on`, formato, confianza mínima, reglas deshabilitadas). La CLI tiene prioridad sobre
el fichero, y el fichero sobre los defaults.
