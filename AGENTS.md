# AGENTS.md — Reglas operativas del proyecto SOC L2 SIEM Analyzer

Contexto:
- Proyecto del Bootcamp SOC L2; el desarrollador es principiante en vibecoding.
- Todo el trabajo ocurre en `C:\Users\Luiggy\SOC_L2_PROJECT` bajo Windows/PowerShell.
- Documénto fuente de verdad: `docs/PLAN.md`. Estado actual: `docs/PROGRESS.md`.

Reglas de oro:
1. **Rigor analítico**: ningún hallazgo, cifra ni afirmación del informe puede existir sin evidencia real de los logs. Si falta evidencia, usar exactamente la frase: **“No hay evidencia en los logs proporcionados.”**
2. **Determinismo primero**: el motor de detección es determinista (reglas YAML + código). La IA solo redacta a partir de hallazgos estructurados, nunca detecta ni inventa.
3. **Sin hardcoding**: no codificar IPs, usuarios, hostnames, nombres de reglas o señales del Excel de ejemplo. Todo entra por YAML/parámetros.
4. **Hecho / Inferencia / Hipótesis**: cada afirmación se marcar explícitamente.
5. **Evidencia con `Log_ID`**: todo hallazgo cita filas concretas abiertas en la UI o el PDF.

Cómo ejecutar y probar (una vez haya esqueleto):
- Arranque local: `.\start.ps1` desde la raíz.
- Tests: `.\test.ps1` o `pytest -q` desde `backend/`.
- Se considera una fase terminada solo cuando: app arranca, tests pasan, se verifica manualmente el criterio de la fase.

Reglas de Git:
- Repo remoto privado: `https://github.com/luiggyencarnacion/SOC-L2-SIEM-Analyzer`.
- **Los commits y el push los hace el desarrollador**, no los agentes/automatizaciones.
- Solo se permite usar Git de lectura: `git status`, `git diff`, `git log`, `git ls-files`. Prohibido `git commit`, `git push`, `git remote`, `git reset --hard`, `git clean`, `git rebase`, cualquier comando con `--force` y cambiar el remoto.
- Antes del primer commit se verifica con `git status` y `git ls-files` que `.gitignore` excluye: `.env`, `.venv`, `node_modules`, `__pycache__`, `dist/`, `build/`, PDFs/informes generados y cualquier archivo de logs cargado (carpeta `data/uploads/`). Solo el Excel sintético de ejemplo puede versionarse.
- Si una clave, token o dato sensible llegara a un archivo no ignorado, avisar de inmediato antes de cualquier commit.
- Sugerir mensajes de commit con formato `fase X: descripción corta`.

Seguridad de la propia app:
- Validar tamaño/tipo/estructura; sin macros ni fórmulas ejecutadas; sanear todo lo renderizado; no exponer secretos; CORS/host restringidos a localhost; CSV protegido contra inyección de fórmulas.
- Nunca ejecutar scripts descargados de internet (`curl | sh` o equivalentes).

Convenciones de trabajo:
- Fases pequeñas y verificables; una fase por sesión preferentemente.
- Antes de escribir código, presentar el objetivo y el criterio de done.
- Al cerrar cada fase: qué quedó hecho, cómo ejecutarlo, cómo verificarlo y qué sigue.
- Dependencias: solo instalar tras aprobación explícita, con versiones fijadas en `requirements.txt` y `package.json`. Nunca global.
- Comandos que borran, sobrescriben o salen del proyecto requieren confirmación previa.
