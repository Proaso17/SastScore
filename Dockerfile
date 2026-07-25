# Imagen de sastcore. Por defecto arranca la APLICACIÓN WEB (pensada para Cloud Run).
#
#   Web (local):  docker build -t sastcore . && docker run --rm -p 8080:8080 sastcore
#                 -> http://127.0.0.1:8080
#   CLI:          docker run --rm -v "$PWD:/src" --entrypoint sastcore sastcore scan /src
FROM python:3.12-slim

LABEL org.opencontainers.image.title="sastcore"
LABEL org.opencontainers.image.description="Motor SAST open-core, multi-lenguaje"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# UTF-8 en todo el proceso (los informes llevan acentos); sin .pyc ni buffering.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUTF8=1 \
    PYTHONIOENCODING=utf-8 \
    PORT=8080

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[web]" && rm -rf /root/.cache

# Usuario sin privilegios (no arrancar como root).
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8080

# Cloud Run inyecta $PORT. Escuchamos en 0.0.0.0 y confiamos en los proxy-headers
# del front-end (para el esquema HTTPS y la IP real del cliente). uvicorn directo
# (no la CLI) para que el proceso de larga vida conserve el GC activado.
CMD ["sh", "-c", "exec uvicorn sastcore.web.app:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1 --proxy-headers --forwarded-allow-ips=* --no-server-header"]
