# Despliega sastcore (aplicación web) en Google Cloud Run.
#
# Requisitos previos (una sola vez):
#   1. Instala Google Cloud SDK:  https://cloud.google.com/sdk/docs/install
#   2. gcloud auth login
#   3. Crea o elige un proyecto en https://console.cloud.google.com (necesita facturación activada)
#
# Uso:
#   .\deploy\deploy.ps1 -ProjectId "mi-proyecto-gcp"
#   .\deploy\deploy.ps1 -ProjectId "mi-proyecto-gcp" -Region "europe-southwest1" -Service "sastcore"

param(
    [Parameter(Mandatory = $true)][string]$ProjectId,
    [string]$Region = "europe-southwest1",
    [string]$Service = "sastcore"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent

Write-Host "==> Proyecto: $ProjectId | Región: $Region | Servicio: $Service"

gcloud config set project $ProjectId
if (-not $?) { throw "No se pudo fijar el proyecto. ¿Has hecho 'gcloud auth login'?" }

Write-Host "==> Habilitando APIs (run, cloudbuild, artifactregistry)..."
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com
if (-not $?) { throw "No se pudieron habilitar las APIs." }

Write-Host "==> Construyendo y desplegando desde el código fuente..."
$deployArgs = @(
    "run", "deploy", $Service,
    "--source", $Root,
    "--region", $Region,
    "--quiet",
    "--allow-unauthenticated",
    "--cpu", "1",
    "--memory", "2Gi",
    "--concurrency", "4",
    "--timeout", "300",
    "--max-instances", "4",
    "--set-env-vars", "SASTCORE_MAX_CONCURRENT_SCANS=2,PYTHONUTF8=1,PYTHONIOENCODING=utf-8"
)
gcloud @deployArgs
if (-not $?) { throw "El despliegue falló." }

Write-Host ""
Write-Host "==> Desplegado. URL pública del servicio:" -ForegroundColor Green
gcloud run services describe $Service --region $Region --format "value(status.url)"
