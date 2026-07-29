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
`SASTCORE_MAX_FILES`, `SASTCORE_SCAN_TIMEOUT_S`, `SASTCORE_RATE_LIMIT_PER_MIN`,
`SASTCORE_RATE_LIMIT_SCANS_PER_MIN`, `SASTCORE_MAX_SCANS_PER_IP`,
`SASTCORE_SCAN_BATCH_FILES`.

### Protección frente a abuso (incluida, sin coste)

| Defensa | Valor | Qué evita |
|---|---|---|
| `SASTCORE_RATE_LIMIT_SCANS_PER_MIN` | 5 | Escaneos por IP y minuto. Cuota **aparte** de las peticiones baratas, porque un escaneo cuesta segundos de CPU. |
| `SASTCORE_MAX_SCANS_PER_IP` | 1 | Que una sola IP ocupe todas las plazas de análisis. |
| `SASTCORE_RATE_LIMIT_PER_MIN` | 20 | Peticiones baratas (informes, compartir, feedback) por IP y minuto. |
| `--max-instances` | 4 | Techo de coste y de daño (se fija al desplegar). |

Las respuestas 429 incluyen `Retry-After`. El rate-limit es en memoria y **por
instancia**: suficiente para un lanzamiento, pero no es un límite global (ver más abajo).

### Sobre `SASTCORE_SCAN_BATCH_FILES` (ficheros por subproceso)

El escaneo se reparte en lotes y cada lote corre en un subproceso nuevo. Arrancar un
proceso cuesta ~1,5 s y analizar un fichero ~0,06 s, así que **cuantos menos lotes,
más rápido**: el valor por defecto (200) es alto a propósito. Si un lote muere sin
producir informe, el escaneo lo parte en dos, reduce el tamaño para los siguientes y
continúa, de modo que un fichero problemático no arruina el análisis completo.

Esto existe porque el binding de tree-sitter se corrompe tras parsear muchos ficheros
en el mismo proceso (**observado en Windows**, ver `docs/adr`). Si en tu despliegue de
Linux no ocurre, el valor alto por defecto ya hace que se use un solo subproceso.

## Enlaces compartibles (opcional)

El botón «Compartir enlace» guarda el informe y devuelve una URL efímera. Sin configurar
nada funciona escribiendo en el disco local de la instancia — válido para probar, pero en
Cloud Run **cada instancia tiene su propio disco efímero**, así que un enlace creado en una
instancia puede no resolverse en otra. Para que funcione de verdad en producción, usa un
bucket de Cloud Storage:

```bash
gcloud storage buckets create gs://TU-BUCKET-informes --location europe-southwest1
gcloud run services update sastcore --region europe-southwest1 \
    --set-env-vars SASTCORE_REPORTS_BUCKET=TU-BUCKET-informes
```

La cuenta de servicio del servicio necesita permiso de lectura/escritura en el bucket
(rol `roles/storage.objectAdmin` sobre ese bucket). El paquete `google-cloud-storage` debe
estar instalado en la imagen (añádelo a `pyproject.toml` si vas a usar GCS).

Ajusta la caducidad con `SASTCORE_REPORT_TTL_HOURS` (por defecto **168 h** = 7 días).
Recomendado además: una **regla de ciclo de vida** en el bucket que borre los objetos
pasados N días, como red de seguridad.

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

Cuando lo tengas, **declara la URL pública** para que se emitan las etiquetas canónicas,
las de redes sociales y el `Sitemap` de `robots.txt` (sin esto se omiten, para no
inventar un dominio):

```bash
gcloud run services update sastcore --region europe-southwest1 \
    --set-env-vars SASTCORE_PUBLIC_URL=https://app.tudominio.com
```

## Bajar o eliminar el servicio

```bash
gcloud run services delete sastcore --region europe-southwest1
```

## WAF (Cloud Armor): lee esto antes de intentarlo

**Cloud Armor no se puede aplicar a la URL `*.run.app`.** Es la limitación clave y
obliga a rehacer la arquitectura:

1. Cloud Armor solo actúa sobre un **balanceador de carga de aplicación externo** con un
   *serverless NEG* apuntando al servicio. No se «activa» sobre Cloud Run directamente.
2. Peor aún: mientras la **URL por defecto `*.run.app` siga activa, el atacante la usa y
   se salta el WAF**. Para cerrarlo hay que desactivar esa URL (ingress
   `internal-and-gclb`), lo que implica **tener dominio propio y certificado**.

**Coste aproximado** (a julio de 2026): regla de reenvío del balanceador ~**18 $/mes**
(0,025 $/hora), política de Cloud Armor **5 $/mes** + **1 $/mes por regla** + ~**0,75 $
por millón de peticiones**. Total realista: **~25-30 $/mes**, frente a los ~0 € actuales
con la capa gratuita de Cloud Run.

**Recomendación:** no montarlo todavía. Sale caro, obliga a abandonar la URL gratuita y
las defensas de la tabla anterior (cuotas por IP, tope de simultáneos, `--max-instances`)
cubren de sobra un lanzamiento sin tráfico. Móntalo cuando se cumpla alguna de estas:

- Recibes abuso real que las cuotas por instancia no frenan (el rate-limit es por
  instancia: con varias instancias, el límite efectivo se multiplica).
- Ya tienes **dominio propio** (que hace falta igualmente para el WAF).
- La factura o el tráfico justifican los ~25-30 $/mes.

Cuando llegue el momento, el orden es: dominio → balanceador con serverless NEG →
política de Cloud Armor (regla `throttle` por IP + reglas OWASP preconfiguradas) →
`--ingress internal-and-gclb` para cerrar la URL directa.

**Alternativa intermedia y gratuita:** poner Cloudflare (plan gratuito) delante del
dominio, que da WAF y rate-limit básicos. Requiere igualmente cerrar el acceso directo a
la URL de Cloud Run para que no se pueda esquivar.

## Cola de trabajos en segundo plano: por qué no la usamos

Puede parecer natural responder al instante y analizar «en segundo plano», pero en
Cloud Run **eso no funciona sin cambiar la facturación**:

- Por defecto, Cloud Run **solo asigna CPU mientras se atiende una petición**. Una tarea
  lanzada tras responder se queda **congelada**.
- Para que corra hay que desplegar con `--no-cpu-throttling` (CPU siempre asignada), que
  cambia el modelo a **facturación por instancia**: pagas todo el ciclo de vida de la
  instancia, no solo el tiempo de petición. Adiós a la economía de «escala a cero».
- Hacerlo bien de verdad (Cloud Tasks + almacenar la subida en GCS + endpoint de worker
  autenticado) es bastante infraestructura para el volumen actual.

**Lo que hacemos en su lugar:** el análisis ocurre **dentro de la petición** (CPU
garantizada) y el servidor **emite el progreso en streaming** (NDJSON) para que la
página muestre «N de M ficheros · X %» en vez de un spinner mudo. Endpoints
`/api/scan-stream` y `/api/scan-url-stream`.

> Nota de rendimiento: los lotes son **grandes a propósito** (`SASTCORE_SCAN_BATCH_FILES`,
> 200). Trocear más fino da más avances, pero medido sobre un repositorio real multiplicó
> por 6 el tiempo y perdió el 64 % de los hallazgos: cuando un lote muere, la recuperación
> lo va partiendo hasta 1 fichero y los que tampoco pasan sueltos se descartan.

## Siguientes pasos (opcionales)

- **CI/CD:** conectar el repo para desplegar en cada push (Cloud Build trigger).
- **Rate-limit global** (Redis/Memorystore) si el límite por instancia se queda corto.
