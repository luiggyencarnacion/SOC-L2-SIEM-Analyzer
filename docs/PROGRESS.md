# PROGRESS.md — Estado del proyecto

Última actualización: fase A implementada (fase 0 cerrada).

## Estado por fase

| Fase | Estado | Notas |
|---|---|---|
| 0 | ✅ completada | Esqueleto: `start.ps1`, `test.ps1`, `.env.example`, `README.md`, `requirements.txt` pinneado, `.venv` creado, frontend `npm install` hecho, `.gitignore` verificado (`data/uploads/` ignorado y confirmado con `git check-ignore`). |
| A | 🔶 implementada — Pendiente: verificación manual del desarrollador | Ingesta + hojas + mapeo + normalización + alias + calidad + tabla. Backend FastAPI (24 tests verdes), frontend React con subida → mapeo → tabla. Pendiente de qué: recorrer la verificación paso a paso con la app arrancada. |
| B1 | pendiente | Reglas AUTH-001–005, AUTH-007, PRIV-001/002, EXEC-001–007, PERS-001–003. |
| B2 | pendiente | Reglas LAT-001–004, EXF-001–004, WEB-001–003. |
| C | pendiente | Correlación, incidentes, scoring y override. |
| D | pendiente | Dashboard interactivo. |
| E | pendiente | Plantillas deterministas + IA (sin chat). |
| F | pendiente | Informe completo y PDF. |
| F2 | pendiente | Chat IA sobre el caso. |
| G | pendiente | Pulido, README, errores, rendimiento, seguridad. |
| H (opcional) | pendiente | AUTH-006, AUTH-008, BASE-001, BASE-002. |

## Fase A — qué quedó hecho

- **Backend** (`backend/app`):
  - `core/config.py`: límites desde `.env` (25 MB, 50 hojas, 100 columnas, 100.000 filas), carpetas de datos, máximo de sesiones en memoria.
  - `ingestion/validator.py`: solo `.xlsx` (rechaza `.xls`, `.xlsm`, corruptos, cifrados, ZIP sin firma `PK` y paquetes con `vbaProject.bin`); lectura con `openpyxl` en modo read-only y `data_only` (no ejecuta macros ni fórmulas); límites por hoja.
  - `ingestion/mapping.py`: detección automática de fila de cabecera y sugerencia de mapeo columna→campo universal con confianza y motivo; validación de estructura mínima (timestamp o al menos una identidad).
  - `ingestion/normalize.py`: normaliza `Event_ID` siempre texto; `Result` → `result_norm` (`success/failure/denied/error/other`) sin perder el original y HTTP codes a `http_status`; timestamps: offset respetado (`valid_offset`), naive como hora de pared (`valid_wall`); IPs validadas con `ipaddress` y clasificadas (privada/pública/loopback/inválida); extracción desde texto libre con regex (IPs, URLs, `DOMINIO\user`, UNC, rutas, Logon Type) marcada en `extracted`; `process_name` derivado del `CommandLine`; `raw` conserva la fila cruda completa para evidencia; `quality_flags` (timestamp inválido, IP inválida, Log_ID sintético).
  - `ingestion/aliases.py`: `exact` / `probable` (misma clave normalizada, valores crudos distintos → inferencia etiquetada, no fusiona por sí solo) / `candidate` (solapamiento fuerte ≥6 caracteres con claves distintas → no se fusionan). El valor crudo nunca se sobrescribe: `host_key`/`user_key` van aparte.
  - `ingestion/quality.py`: nulos por campo con %, distintos, duplicados de `Log_ID`, distribución del timestamp (wall/offset/inválidos/faltantes), distribución de `result_norm`, columnas con tipos mezclados.
  - `services/analysis.py` + `services/sessions.py`: pipeline hoja→mapeo→normaliza→calidad; sesiones en memoria con tope (expulsa la más antigua); borrado asegura eliminación del archivo subido.
  - `api/routes_ingestion.py`: `POST /api/upload` (devuelve hojas con dimensiones, vista previa, sugerencias de mapeo con confianza), `POST /api/sessions/{id}/analyze` (hoja + fila de cabecera + mapeo; relectura si se cambia la cabecera), `GET /api/sessions/{id}/events` (paginación `page_size` hasta 250, búsqueda global `q`, filtros JSON por columna (`host_raw`, `user_raw`, `source_ip`, `destination_raw`, `result_raw`, `severity_siem`, `log_source`, `event_code`, `timestamp_raw`), orden por cualquier campo con asc/desc), `GET /api/sessions/{id}/events/{Log_ID}` (fila cruda con columnas), `GET .../quality`, `GET .../aliases`, `GET /api/sessions/{id}`, `DELETE /api/sessions/{id}`, `GET /api/health`.
  - CORS solo `127.0.0.1:5173/4173` y proxy de Vite; mensajes de error en español sin trazas internas; Log_ID inexistente responde 404 con la frase exacta: "No hay evidencia en los logs proporcionados con Log_ID '<id>'."
- **Frontend** (`frontend/src`, React 19 + TS 5.9 + Tailwind 4 + Vite 8):
  - Subida por drag&drop con rechazo local y mensajes del backend.
  - Editor de mapeo por hoja: vista previa de 5 filas, selector de campo universal por columna con confianza/motivo, fila de cabecera editable, cambio de hoja.
  - Tabla: paginación 50/100/250, búsqueda global, filtros por columna, orden al hacer clic en cabecera, chips de `result_norm`, panel de evidencia de fila cruda al hacer clic (campos normalizados + valores literales de la fila con nombres de columna + `quality_flags`).
  - Paneles: calidad de datos (KPIs, nulos por campo, duplicados, tipos mezclados, distribución de `result_norm`) y alias (exact/probable/candidate con explicación de política).
- **Tests** (`backend/tests`, 24 pasando):
  - Validador: extensión, firma, macros, corruptos, carga del Excel de ejemplo.
  - Normalización/alias: claves `DC-01`/`DC01` → `dc01`, `backupsvc` vs `svc_backup` candidate no fusionado e inferencia etiquetada; timestamps naive/offset/inválidos; `Result` y HTTP codes; IPs y scopes; `process_name` desde CommandLine.
  - API end-to-end con `TestClient`: upload inválido/valido, analyze, 715 filas, paginación, búsqueda, **filtro por columna validado por contenido** (no solo total), orden, detalle crudo, calidad, aliases, delete; estructura mínima insuficiente → 400; Log_ID sintético `ROW-N` cuando no hay columna `log_id`.

## Validación contra el Excel de ejemplo (715 filas)

- Mapeo automático con confianza 100% en las 12 columnas (sin hardcodear descubrimiento: usa sinónimos genéricos en campo nombres de columnas estandarizados).
- 715 filas normalizadas; timestamps: 715 válidos (hora de pared, sin zona); duplicados de Log_ID: 0.
- Alias detectados: `DC-01 ↔ DC01` como **probable** (inferencia, no fusionados por sí solos); `CORP\backupsvc ↔ CORP\svc_backup` como **candidate** (no se fusionan).
- Distribución `result_norm`: success 598 · failure 108 · error 9 (coherente con códigos HTTP 200/404/500 mapeados a success/failure/error).

## Decisiones tomadas

- Fase A no usa pandas: `openpyxl` read-only + `data_only` alcanza para leer sin ejecutar fórmulas; pandas se puede incorporar después si se necesita para el dashboard.
- Los filtros de tabla se formulan con nombres normalizados de campo (`host_raw`, etc.); los nombres exactos de columna cruda pueden variar por archivo.
- Los archivos subidos se guardan en `data/uploads/<uuid>.xlsx` (git-ignorado) durante la vida de la sesión y se borran al eliminar la sesión; no se requiere re-subir al cambiar mapeo o cabecera.
- Sesiones evictadas víctima de tope de sesiones dejan su archivo en `data/uploads/` hasta cerrarse de forma ordenada (limpieza manual de restos previstos en fase G).
- Alias: `created/confirmed/rejected` por analista llega con la correlación (fase C); fase A solo detecta base.
- "Unir todas las hojas" se pospone a la integración multi-hoja (no es crítico: el archivo de ejemplo tiene 1 hoja); fase A analiza hojas de forma independiente.

## Pendientes inmediatos

- Verificación manual de la fase A por el desarrollador (lista de pasos en la conversación y en la sección "Cómo ejecutar y probar" abajo).
- Si conviene, limpiar restos de `data/uploads/` de las sesiones que murieron con la recarga del servidor (git-ignorado, sin riesgo de commit).
- Al hacer commit (lo hace el desarrollador): sugerencia de mensaje → `fase A: ingestion, mapping, normalization, aliases, quality y tabla de eventos (backend+frontend+tests)`.

## Cómo ejecutar y probar (fase A)

- Arrancar todo: `.\start.ps1` (backend en http://127.0.0.1:8000 · frontend en http://127.0.0.1:5173).
- Arrancar solo backend: `.\start.ps1 -SkipFrontend` · solo frontend: `.\start.ps1 -SkipBackend`.
- Tests: `.\test.ps1`  (o `cd backend; .\..\.\.venv\Scripts\python.exe -m pytest -q`).
- API docs interactivas: http://127.0.0.1:8000/docs
- Verificación de fase A (criterio): subir `data/sample/...xlsx`, ver 715 filas normalizadas, buscar/filtrar/ordenar en la tabla, cambiar hoja/mapeo/fila de cabecera y re-analizar, revisar alias (probable/candidate) y nulos, intentar subir un `.csv`/`.xls`/archivo corrupto y ver el rechazo con mensaje en español.

## Recordatorios

- Regla de oro: todo hallazgo debe tener evidencia con `Log_ID`; si no, frase exacta: "No hay evidencia en los logs proporcionados."
- Reglas de Git de `AGENTS.md` se respetan antes de cualquier commit (commit y push los hace el desarrollador).
- La IA no detecta: entra en fase E, y solo redacta a partir de hallazgos deterministas.
