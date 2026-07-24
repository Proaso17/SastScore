# sastcore

Motor **SAST** (análisis estático de seguridad) open-core, multi-lenguaje, orientado a CI/CD.

No es un linter de estilo: cada hallazgo tiene una vulnerabilidad explicable detrás,
mapeada a **CWE** y **OWASP Top 10**. El objetivo es alta señal y baja tasa de falsos
positivos, con salida **SARIF 2.1.0** nativa y **cero telemetría** (no hace llamadas de
red durante el escaneo).

> **Estado: MVP completo (Fase 6).** Discovery + secretos + patrones (36 reglas) + **taint
> analysis** (traza source→sink), reporters SARIF/HTML/Markdown/JUnit, modo baseline y cache,
> más **GitHub Action, hook de pre-commit, imagen Docker, `sastcore init`** y guía para
> escribir reglas. Ver [el roadmap](#roadmap) y [docs/](docs/).

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
sastcore init                                # genera .sastcore.yml
sastcore scan .                              # secretos + patrones + taint
sastcore scan . --fail-on HIGH               # exit 1 si hay hallazgos HIGH o superiores
sastcore scan . --format sarif -o out.sarif  # SARIF 2.1.0 para GitHub Code Scanning
sastcore scan . --format html -o report.html # informe HTML autocontenido
sastcore baseline create . -o baseline.json  # snapshot de fingerprints
sastcore scan . --baseline baseline.json     # solo hallazgos nuevos
```

**Más:** [guía para escribir reglas](docs/writing-rules.md) ·
[integración en CI/CD (GitHub Action, Docker, pre-commit)](docs/ci-integration.md).

Códigos de salida (contrato estable para CI): `0` limpio · `1` hallazgos sobre el umbral ·
`2` error de ejecución.

## Roadmap

| Fase | Contenido | Estado |
|------|-----------|--------|
| 0 | Fundaciones: repo, tooling, CI, CLI stub | ✅ hecha |
| 1 | Discovery + pasada de secretos (regex + entropía) | ✅ hecha |
| 2 | Parsing tree-sitter + motor de patrones (metavariables, elipsis) | ✅ hecha |
| 3 | Rulepacks core (~31 reglas, OWASP Top 10) | ✅ hecha |
| 4 | Taint analysis (CFG → DFG → propagación → summaries) | ✅ hecha |
| 5 | Reporters (SARIF/HTML/MD/JUnit) + modo baseline/CI | ✅ hecha |
| 6 | Integraciones (GitHub Action, pre-commit, Docker) + DX | ✅ hecha |

Lenguajes del MVP: **JavaScript, TypeScript, Python**.

## Arquitectura

Las decisiones de diseño no obvias se documentan como ADRs en
[`docs/adr/`](docs/adr/). Visión general en
[`docs/architecture.md`](docs/architecture.md).

## Licencia

[Apache-2.0](LICENSE).
