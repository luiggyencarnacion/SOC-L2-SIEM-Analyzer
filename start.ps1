# start.ps1 — Arranque local del proyecto SOC L2 SIEM Analyzer
# Uso: .\start.ps1   (desde la raiz del proyecto)
# Restricciones del plan: bind solo en 127.0.0.1, sin instalaciones globales.
param(
    [switch]$SkipFrontend,
    [switch]$SkipBackend
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Write-Step($msg) { Write-Host "[start] $msg" -ForegroundColor Cyan }
function Write-WarnLocal($msg) { Write-Host "[start] AVISO: $msg" -ForegroundColor Yellow }
function Write-ErrLocal($msg) { Write-Host "[start] ERROR: $msg" -ForegroundColor Red }

# --- Verificaciones previas ---
if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-ErrLocal "No existe .venv. Crealo primero: python -m venv .venv ; .\.venv\Scripts\python.exe -m pip install -r requirements.txt"
    exit 1
}

$backendHasApp = Test-Path ".\backend\app\main.py"
$frontendHasDeps = Test-Path ".\frontend\node_modules"

if (-not $backendHasApp -and -not $SkipBackend) {
    Write-WarnLocal "backend/app/main.py aun no existe (fase 0). Solo se arrancara el frontend si existe."
}

if (-not $frontendHasDeps) {
    Write-WarnLocal "frontend/node_modules no existe. Ejecuta: cd frontend ; npm install"
}

$procs = @()

# --- Backend (uvicorn) ---
if (-not $SkipBackend -and $backendHasApp) {
    Write-Step "Arrancando backend en http://127.0.0.1:8000 ..."
    $procs += Start-Process -FilePath ".\.venv\Scripts\python.exe" `
        -ArgumentList "-m","uvicorn","app.main:app","--host","127.0.0.1","--port","8000","--reload" `
        -WorkingDirectory "$root\backend" `
        -PassThru -WindowStyle Hidden
    Write-Step "API docs: http://127.0.0.1:8000/docs"
}
elseif (-not $SkipBackend) {
    Write-Step "Backend omitido: aun no hay app (fase 0)."
}

# --- Frontend (vite dev) ---
if (-not $SkipFrontend -and $frontendHasDeps) {
    Write-Step "Arrancando frontend en http://127.0.0.1:5173 ..."
    $npmPath = (Get-Command npm.cmd -ErrorAction SilentlyContinue).Source
    if (-not $npmPath) {
        Write-ErrLocal "npm (npm.cmd) no esta disponible en el PATH."
        exit 1
    }
    $procs += Start-Process -FilePath $npmPath `
        -ArgumentList "run","dev" `
        -WorkingDirectory "$root\frontend" `
        -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Write-Step "Frontend: http://127.0.0.1:5173"
}
elseif (-not $SkipFrontend) {
    Write-Step "Frontend omitido: faltan dependencias node."
}

if ($procs.Count -eq 0) {
    Write-WarnLocal "No se ha arrancado nada (proyecto en fase 0)."
    exit 0
}

Write-Step "Procesos arrancados:"
$procs | ForEach-Object { Write-Host ("  PID {0}" -f $_.Id) }
Write-Step "Pulsa Ctrl+C o cierra esta consola para detenerlos (los procesos quedan vivos; usa Stop-Process si hace falta)."
try { Wait-Process -Id ($procs | ForEach-Object Id) -ErrorAction SilentlyContinue } catch {}
