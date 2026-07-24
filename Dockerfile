# Imagen slim de sastcore. Uso:
#   docker build -t sastcore .
#   docker run --rm -v "$PWD:/src" sastcore scan /src --fail-on HIGH
FROM python:3.12-slim

LABEL org.opencontainers.image.title="sastcore"
LABEL org.opencontainers.image.description="Motor SAST open-core, multi-lenguaje"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /root/.cache

# El código del usuario se monta aquí (docker run -v "$PWD:/src").
WORKDIR /src
ENTRYPOINT ["sastcore"]
CMD ["scan", "."]
