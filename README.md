# sastcore

Motor **SAST** (análisis estático de seguridad) open-core, multi-lenguaje, orientado a CI/CD.

No es un linter de estilo: cada hallazgo tiene una vulnerabilidad explicable detrás,
mapeada a **CWE** y **OWASP Top 10**. El objetivo es alta señal y baja tasa de falsos
positivos, con salida **SARIF 2.1.0** nativa y **cero telemetría** (no hace llamadas de
red durante el escaneo).

> **Estado: Fase 2.** Discovery + secretos + **motor de patrones** (tree-sitter, con
> metavariables y elipsis) y rulepacks YAML operativos, con supresión inline. Salida en
> consola y JSON. El taint analysis llega en la Fase 4. Ver [el roadmap](#roadmap).

## Instalación (desarrollo)

Requiere **Python 3.11+** (en Windows, usar el launcher: `py -3.12`).

```bash
py -3.12 -m venv .venv
.venv\Scripts\activate        # PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Uso

```bash
sastcore --version
sastcore scan .                       # escanea en busca de secretos
sastcore scan . --format json         # salida JSON
sastcore scan . --fail-on HIGH        # exit 1 si hay hallazgos HIGH o superiores
```

Códigos de salida (contrato estable para CI): `0` limpio · `1` hallazgos sobre el umbral ·
`2` error de ejecución.

## Roadmap

| Fase | Contenido | Estado |
|------|-----------|--------|
| 0 | Fundaciones: repo, tooling, CI, CLI stub | ✅ hecha |
| 1 | Discovery + pasada de secretos (regex + entropía) | ✅ hecha |
| 2 | Parsing tree-sitter + motor de patrones (metavariables, elipsis) | ✅ hecha |
| 3 | Rulepacks core (~40 reglas, OWASP Top 10) | ⚪ pendiente |
| 4 | Taint analysis (CFG → DFG → propagación → summaries) | ⚪ pendiente |
| 5 | Reporters (SARIF/HTML/MD/JUnit) + modo baseline/CI | ⚪ pendiente |
| 6 | Integraciones (GitHub Action, pre-commit, Docker) + DX | ⚪ pendiente |

Lenguajes del MVP: **JavaScript, TypeScript, Python**.

## Arquitectura

Las decisiones de diseño no obvias se documentan como ADRs en
[`docs/adr/`](docs/adr/). Visión general en
[`docs/architecture.md`](docs/architecture.md).

## Licencia

[Apache-2.0](LICENSE).
