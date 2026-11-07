# test.ps1 — Ejecuta la suite de tests del proyecto SOC L2 SIEM Analyzer
# Uso: .\test.ps1   (desde la raiz del proyecto)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Host "[test] ERROR: No existe .venv. Crealo primero: python -m venv .venv" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path ".\backend\tests")) {
    Write-Host "[test] Aviso: backend\tests aun no existe (fase 0). No hay tests que ejecutar." -ForegroundColor Yellow
    exit 0
}

Write-Host "[test] Ejecutando pytest en backend/ ..." -ForegroundColor Cyan
Push-Location "$root\backend"
& $root\.venv\Scripts\python.exe -m pytest -q
$code = $LASTEXITCODE
Pop-Location

if ($code -eq 0) {
    Write-Host "[test] OK: suite verde." -ForegroundColor Green
} else {
    Write-Host "[test] FALLO: exit code $code" -ForegroundColor Red
}
exit $code
