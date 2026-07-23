# 0002 — Identidad del hallazgo y fingerprint

- **Estado:** Aceptado
- **Fecha:** 2026-07-23

## Contexto

El modo baseline/diff de CI depende de poder decir "este hallazgo es el mismo que el de
la ejecución anterior". Eso requiere una **identidad estable** por hallazgo. La propuesta
inicial era `sha256(rule_id + path_relativo + snippet_normalizado)`.

Esa fórmula es estable si el código se mueve de línea sin cambiar (bien), pero tiene dos
fallos que rompen el baseline en la práctica:

1. **Renombrar o mover un fichero** cambia `path_relativo`, y todos sus hallazgos
   aparecen como "nuevos" en el diff.
2. **Snippet duplicado en dos ficheros** (un helper copiado) colisiona: el dedup pierde
   uno de los dos.

## Decisión

Adoptar un modelo de **`partialFingerprints` al estilo SARIF**, que además alinea el
dedup de sastcore con el de **GitHub Code Scanning** (usa ese campo para casar resultados
entre ejecuciones):

- **Identidad primaria** = `hash(rule_id + contexto_rodante_normalizado + índice_de_ocurrencia)`,
  donde el contexto son ±N líneas normalizadas alrededor del match (resistente a mover el
  bloque y a renombrar el fichero), e `índice_de_ocurrencia` desambigua repeticiones
  dentro del mismo fichero.
- **`path`** pasa a ser un componente **secundario/soft**: se usa para presentación y
  desempate, no forma parte de la identidad.

Esto **supersede** la fórmula literal de la especificación original del `Finding`:
se conserva el requisito (estabilidad ante movimiento de líneas) y se cambia la
implementación para que además sobreviva a renombrados y duplicados.

## Consecuencias

- **A favor:** baseline robusto ante refactors de estructura; interoperable con GitHub
  Code Scanning; menos "falsos nuevos" en el diff de CI.
- **En contra:** el contexto rodante debe normalizarse con cuidado (espacios, comentarios)
  para no ser ni demasiado frágil ni demasiado laxo; hay que elegir y documentar `N`.
