# SOC L2 SIEM Analyzer

Aplicación web local para un analista SOC Nivel 2: carga de logs exportados de un SIEM en `.xlsx`, detección por reglas YAML deterministas, correlación en incidentes, scoring de riesgo, dashboard y informe técnico editable exportable a PDF.

> Documentación fuente de verdad: [`docs/PLAN.md`](docs/PLAN.md). Estado actual: [`docs/PROGRESS.md`](docs/PROGRESS.md).

## Requisitos

- Windows 10/11, PowerShell
- Python 3.13 instalado
- Node.js 26.x + npm 11.x instalados
- (Opcional para Fase 0) Chromium en caché de Playwright

## Puesta a punto (una sola vez)

```powershell
# 1. Entorno virtual Python + dependencias
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# 2. Dependencias del frontend
cd frontend
npm install
cd ..
```

## Arranque

```powershell
.\start.ps1
```

- Backend (cuando exista): http://127.0.0.1:8000 — documentación API en `/docs`
- Frontend (Vite dev): http://127.0.0.1:5173
- Solo bind en `127.0.0.1` / `localhost`, restringido en firewall si se abre el puerto.

## Tests

```powershell
.\test.ps1
```

## Estructura

```
backend/    FastAPI + motor de reglas YAML + informe (documentación en docs/PLAN.md)
frontend/   React 19 + Vite 8 + TypeScript + Tailwind 4
data/       uploads/ (ignorada), exports/ (ignorada), sessions/ (ignorada), sample/
docs/       PLAN.md (plan aprobado), PROGRESS.md (estado)
```

## Seguridad y reglas del proyecto

- No se suben `.env`, logs cargados ni PDFs con datos al repositorio (ver `.gitignore`).
- No se hardcodean IPs, usuarios ni hallazgos del Excel de ejemplo: todo pasa por reglas YAML.
- La IA no detecta: solo redacta hallazgos estructurados (por defecto `AI_PROVIDER=none`).

## Estado del proyecto

Ver [`docs/PROGRESS.md`](docs/PROGRESS.md). Fase actual: **0 (documentos base)** — aún no hay código de la aplicación.
