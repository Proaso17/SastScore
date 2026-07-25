#!/usr/bin/env bash
# Despliega sastcore (aplicación web) en Google Cloud Run.
#
# Requisitos previos (una sola vez):
#   1. Instala Google Cloud SDK:  https://cloud.google.com/sdk/docs/install
#   2. gcloud auth login
#   3. Crea o elige un proyecto (necesita facturación activada)
#
# Uso:
#   ./deploy/deploy.sh mi-proyecto-gcp
#   ./deploy/deploy.sh mi-proyecto-gcp europe-southwest1 sastcore
set -euo pipefail

PROJECT_ID="${1:?Uso: deploy.sh PROJECT_ID [REGION] [SERVICE]}"
REGION="${2:-europe-southwest1}"
SERVICE="${3:-sastcore}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Proyecto: $PROJECT_ID | Región: $REGION | Servicio: $SERVICE"

gcloud config set project "$PROJECT_ID"

echo "==> Habilitando APIs (run, cloudbuild, artifactregistry)..."
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com

echo "==> Construyendo y desplegando desde el código fuente..."
gcloud run deploy "$SERVICE" \
    --source "$ROOT" \
    --region "$REGION" \
    --quiet \
    --allow-unauthenticated \
    --cpu 1 \
    --memory 2Gi \
    --concurrency 4 \
    --timeout 300 \
    --max-instances 4 \
    --set-env-vars "SASTCORE_MAX_CONCURRENT_SCANS=2,PYTHONUTF8=1,PYTHONIOENCODING=utf-8"

echo ""
echo "==> Desplegado. URL pública del servicio:"
gcloud run services describe "$SERVICE" --region "$REGION" --format "value(status.url)"
