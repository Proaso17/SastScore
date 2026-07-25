# Desplegar sastcore en Google Cloud Run

La aplicación web se empaqueta en la imagen Docker de la raíz del repo y se despliega en
[Cloud Run](https://cloud.google.com/run): contenedor con **HTTPS automático**, **escala a
cero** (pagas solo por uso) y **sandbox gVisor**. No hace falta subir el código a GitHub: el
despliegue sube el código directamente a Cloud Build.

## 1. Requisitos (una sola vez)

1. **Instala el Google Cloud SDK** (`gcloud`): <https://cloud.google.com/sdk/docs/install>
2. **Inicia sesión:**
   ```bash
   gcloud auth login
   ```
3. **Crea un proyecto** en la [consola de Google Cloud](https://console.cloud.google.com/) y
   **activa la facturación** (Cloud Run tiene una capa gratuita generosa; sin facturación no
   deja desplegar). Apunta el *Project ID* (p. ej. `sastcore-prod`).

## 2. Desplegar

Desde la raíz del repositorio:

**Windows (PowerShell):**
```powershell
.\deploy\deploy.ps1 -ProjectId "TU_PROJECT_ID"
```

**Linux / macOS / Git Bash:**
```bash
./deploy/deploy.sh TU_PROJECT_ID
```

El script habilita las APIs necesarias, construye la imagen con Cloud Build y crea el
servicio. La primera vez tarda unos minutos. Al terminar imprime la **URL pública**, del
tipo `https://sastcore-xxxxxxxxxx-ew.a.run.app`. Esa es la que compartes con los usuarios.

> La región por defecto es `europe-southwest1` (Madrid). Cámbiala con `-Region` /
> segundo argumento si prefieres otra.

## 3. Redesplegar (nuevas versiones)

Vuelve a ejecutar el mismo comando: Cloud Run publica una revisión nueva y mueve el tráfico
sin cortes. La URL no cambia.

## 4. Ver logs y estado

```bash
gcloud run services describe sastcore --region europe-southwest1
gcloud run services logs read sastcore --region europe-southwest1 --limit 100
```
O en la consola: **Cloud Run → sastcore → Registros**.

## Configuración aplicada

| Ajuste | Valor | Por qué |
|---|---|---|
| `--allow-unauthenticated` | sí | Servicio público, para todos los usuarios. |
| `--memory` | 2Gi | tree-sitter + el subproceso de escaneo + el zip descomprimido (en `/tmp`, que es RAM). |
| `--cpu` | 1 | El análisis es intensivo en CPU. |
| `--concurrency` | 4 | Peticiones simultáneas por instancia. |
| `--max-instances` | 4 | Techo de coste y de daño ante abuso. |
| `--timeout` | 300 | Margen sobre el timeout de escaneo (180 s). |
| `SASTCORE_MAX_CONCURRENT_SCANS` | 2 | Escaneos pesados a la vez por instancia. |

Otras variables de entorno que puedes ajustar (con `--set-env-vars`):
`SASTCORE_MAX_UPLOAD_BYTES` (máx. **32 MiB** en Cloud Run), `SASTCORE_MAX_UNCOMPRESSED_BYTES`,
`SASTCORE_MAX_FILES`, `SASTCORE_SCAN_TIMEOUT_S`, `SASTCORE_RATE_LIMIT_PER_MIN`.

## Endurecido de seguridad (ya incluido)

- Cabeceras: **CSP** estricta (`script-src 'self'`), `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy` y **HSTS** sobre HTTPS.
- **Rate-limit** por IP y **tope de concurrencia** por instancia (429 si se supera).
- Subida limitada (tamaño, nº de ficheros, tamaño descomprimido) y extracción de zip
  endurecida (anti *zip-slip* / *zip-bomb* / symlinks).
- El código subido **no se ejecuta** (solo se parsea) y **no se almacena**; corre en un
  subproceso aislado dentro del sandbox de Cloud Run.
- Documentación interactiva (`/docs`) desactivada.
- Contenedor como usuario **no-root**.

> El rate-limit es en memoria y **por instancia** (best-effort). Para un límite global real
> ante escala, pon un proxy/WAF delante o un almacén compartido (Redis); ver «Siguientes pasos».

## Dominio propio (más adelante)

Cuando quieras usar tu dominio en vez del `*.run.app`:
```bash
gcloud beta run domain-mappings create --service sastcore \
    --domain app.tudominio.com --region europe-southwest1
```
Sigue las instrucciones para añadir los registros DNS; el certificado TLS es automático.

## Bajar o eliminar el servicio

```bash
gcloud run services delete sastcore --region europe-southwest1
```

## Siguientes pasos (opcionales)

- **CI/CD:** conectar el repo para desplegar en cada push (Cloud Build trigger).
- **Rate-limit global / WAF:** Cloud Armor delante de Cloud Run.
- **Cola de trabajos** para repos muy grandes (procesar en segundo plano).
