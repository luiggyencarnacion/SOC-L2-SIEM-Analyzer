# PROGRESS.md — Estado del proyecto

Última actualización: fase F implementada (informe completo, PDF con portada/índice/paginación y exportaciones CSV/JSON; fases 0, A, B1, B2, C, D y E cerradas). Post-F: ajustes de IA editables desde la UI (clave solo en memoria) + **dos rondas de pulido de presentación del informe** (ver "Pulido 2 de presentación del informe" al final).

## Estado por fase

| Fase | Estado | Notas |
|---|---|---|
| 0 | ✅ completada | Esqueleto: `start.ps1`, `test.ps1`, `.env.example`, `README.md`, `requirements.txt` pinneado, `.venv` creado, frontend `npm install` hecho, `.gitignore` verificado (`data/uploads/` ignorado y confirmado con `git check-ignore`). |
| A | 🔶 implementada — Pendiente: verificación manual del desarrollador | Ingesta + hojas + mapeo + normalización + alias + calidad + tabla. Backend FastAPI, frontend React con subida → mapeo → tabla. |
| B1 | ✅ implementada — Pendiente: verificación manual del desarrollador | Reglas AUTH-001–005, AUTH-007, PRIV-001/002, EXEC-001–007, PERS-001–003. Motor determinista en `backend/app/detection/` con YAML configurable (`detection/rules/default_rules.yaml`), hallazgos con evidencia por `Log_ID`, afirmaciones Hecho/Inferencia/Hipótesis, cobertura por regla. Absorción AUTH-001→AUTH-002 funcionando (spray del ejemplo: 33 fallos absorbidos, 0 hallazgos AUTH-001). |
| B2 | ✅ implementada — Pendiente: verificación manual del desarrollador | Reglas LAT-001–004, EXF-001–004, WEB-001–003. LAT-001 anclado a acceso externo (validado con EVT-00188→EVT-00222/225/227/231), LAT-003 exige ≥2 saltos (1 salto → sin hallazgo), LAT-004 `insufficient_data` documentado (requiere línea base, fase H). Endpoints `GET /findings`, `GET /coverage`, `GET /detection/rules`. Frontend: panel de hallazgos (evidencia clickeable que filtra la tabla) y panel de cobertura. |
| C | ✅ implementada — Pendiente: verificación manual del desarrollador | Correlación, incidentes, scoring y override. Módulo `backend/app/correlation/` (config YAML + scoring + correlador). El Excel de ejemplo produce **6 cadenas** (I-001..I-006, PLAN §14), relaciones "mismo activo", timeline/IoCs/MITRE/kill chain solo observadas, scoring con invariantes del PLAN 7 y override manual con motivo obligatorio. Endpoints `GET /api/sessions/{id}/incidents` y `POST /api/sessions/{id}/overrides`. Frontend: `IncidentsPanel` con override desde la UI y badge de score/override en hallazgos. |
| D | ✅ implementada — Pendiente: verificación manual del desarrollador | Dashboard interactivo. Endpoint `GET /api/sessions/{id}/stats` con agregados deterministas (KPIs, timeline por horas/días, tops, SIEM vs calculada, heatmap, MITRE) y filtro temporal `time_from`/`time_to` en `GET /events`. Frontend: navegación por pestañas (Dashboard · Incidentes · Hallazgos · Redacción · Cobertura · Eventos · Calidad · Alias) y `DashboardPanel` con Recharts; los gráficos filtran (drill-down a hallazgos y tabla de eventos), heatmap hora×día clicable y comparación SIEM vs calculada. |
| E | 🔶 implementada — Pendiente: verificación manual del desarrollador | Plantillas deterministas, adaptadores IA y anti-alucinación (PLAN §10). `backend/app/reporting/templates.py` genera toda la redacción sin IA; `backend/app/ai/` con adaptadores REST `httpx` (gemini, anthropic, openai_compatible, ollama; sin SDKs), enmascaramiento reversible para proveedores cloud y validador anti-alucinación (citas `Log_ID`, entidades, horas y cifras ≥3 dígitos verificadas contra la evidencia; párrafo inválido → descarte con motivo + fallback a plantilla). Endpoints `GET /api/ai/settings`, `POST /api/ai/test` (nunca devuelve la clave), `POST/GET /api/sessions/{id}/narrative`. Frontend: pestaña "Redacción" con ajustes (estado de clave oculto + prueba de conexión), generación y párrafos etiquetados Hecho/Inferencia/Hipótesis con citas clickeables. |
| F | 🔶 implementada — Pendiente: verificación manual del desarrollador | Informe completo (PLAN §9: 14 secciones numeradas + 3 anexos), edición y regeneración de secciones por el analista, PDF A4 con Playwright/Chromium (portada, índice, numeración de páginas, tablas y evidencia con `Log_ID`) y exportaciones IoCs CSV (anti-inyección de fórmulas) y hallazgos JSON. Pestaña nueva "Informe" en la UI. |
| F2 | pendiente | Chat IA sobre el caso. |
| G | pendiente | Pulido, README, errores, rendimiento, seguridad. |
| H (opcional) | pendiente | AUTH-006, AUTH-008, BASE-001, BASE-002 (LAT-004 también quedaría aquí). |

## Fase B (B1+B2) — qué quedó hecho

### Backend (`backend/app/detection/`)
- **`rules/default_rules.yaml`**: las 29 reglas aprobadas (PLAN 6.2) con `id`, `name`, `category`, `description`, `rationale`, `base_severity`, `enabled`, `required_fields`, `optional_fields`, `parameters` (umbrales/patrones configurables, sin hardcodear señales), `mitre`, `evidence_limit`, `use_probable_aliases`. `EXEC-004` y `WEB-003` con `base_severity: Crítico`.
- **`loader.py`**: carga y validación estricta del YAML (campos obligatorios, severidad válida, id duplicada, tipos); error rápido `DetectionConfigError`; caché de lectura.
- **`context.py`**: índice temporal de eventos (`_ts` cacheado y limpiado al final), ventanas deslizantes (hueco máximo desde el inicio de la ventana), getters de campos abreviados del YAML, `is_logon_event` (códigos 4624/4625/4776 + frases declaradas), `concat_text` para matching de patrones.
- **`findings.py`**: constructor de `Finding` con `finding_id` (F-001..), `entities` (usuarios/hosts/IPs/destinos con valores crudos), `evidence_log_ids` (limitado por `evidence_limit`, con `total_evidence` y `evidence_omitted`), `time_range`, `statements` {hecho, inferencia, hipótesis} y `absorbed_detail`.
- **`impl/`**: 7 módulos con la lógica de cada regla:
  - `auth.py`: AUTH-002 se ejecuta **antes** que AUTH-001/AUTH-004 (orden `RULE_ORDER_OVERRIDE`) y absorbe los fallos de las víctimas del spray (`absorbed_detail.auth_001_absorvidas`); el éxito de la víctima (AUTH-003) nunca se absorbe. Anti-ruido: cluster de spray exige ≥5 usuarios, ≤6 fallos por víctima y (origen público **o** ≥8 intentos totales). AUTH-007: cuentas con patrón `svc/helpdesk/backup` (configurable) con logon interactivo (4624/4672) + condición extra (éxito/4672 desde IP pública **o** persistencia del mismo usuario en el mismo host); la actividad normal de helpdesk sola no dispara.
  - `privilege.py`: PRIV-001 por códigos (4720/…/4740); PRIV-002 = 4672 con origen de scope público (agrupado por usuario/origen/host).
  - `execution.py`: EXEC-001 (banderas de evasión PS), EXEC-002 (recon; regex y literales), EXEC-003 (lollbins), EXEC-004 (vssadmin/wmic delete shadows), EXEC-005 (compresión sobre staging/sensible), EXEC-006 (binario en ruta no estándar), EXEC-007 (4104 con contenido relevante + pares padre-hijo configurables).
  - `persistence.py`: PERS-001 (4698 con TaskName/Action extraídos), PERS-002 (7045/4697 con ServiceName/ImagePath), PERS-003 (≥4 ejecuciones del mismo comando con intervalos ≤30 min).
  - `lateral.py`: LAT-001 (ancla = logon exitoso con IP pública; lateral = LogonType 3, share 5140/5145, UNC o `source=<host>` en otro host en 30 min), LAT-002 (shares sensibles esporádicos; el torrente masivo lo cubre EXF-004), LAT-003 (solo ≥2 saltos con ancla), LAT-004 (`insufficient_data` documentado; fase H).
  - `exfil.py`: EXF-001 (5156 a destino externo desde proceso inusual), EXF-002 (POSTs repetidos y/o bytes_out ≥50 MB; suma `bytes_out=` del texto), EXF-003 (subidas periódicas al mismo destino), EXF-004 (≥10 accesos 4663 a carpeta sensible por identidad).
  - `web.py`: los eventos web se resuelven genéricamente (`url_path` **o** comando **o** destino, porque la URL puede venir en columnas distintas según el export). WEB-001 (ráfaga 404/500 ≥10/15 min por origen), WEB-002 (≥5 peticiones login/admin por origen), WEB-003 (parámetro de comando en URL con shell y/o proceso hijo bajo identidad de app pool).
- **`engine.py`**: orden con override (AUTH-002→AUTH-001→AUTH-004, resto por id), cobertura por regla con estados `executed / executed_no_findings / skipped_disabled / skipped_missing_fields / insufficient_data / error` (un error de una regla no rompe el análisis), re-numeración temporal de hallazgos, resumen por severidad y `elapsed_ms`.
- **Normalización (fase A ampliada)**: `normalize.py` extrae desde texto libre `LogonType=N`, `source=<host>`, `bytes_out=N`, `TaskName/Action/ServiceName/ImagePath` (siempre marcados como extraídos); `validate_ip` clasifica por redes explícitas: RFC1918 = private, documentación (192.0.2/24, 198.51.100/24, 203.0.113/24) y CGNAT = public (ipaddress los marca privados en Python 3.13, pero no son RFC1918).
- **Integración**: `run_detection` se ejecuta al final de `run_analysis`; endpoints nuevos `GET /api/detection/rules`, `GET /api/sessions/{id}/findings` (filtros `severity`/`rule`/`q`), `GET /api/sessions/{id}/coverage`; `analyze` devuelve `detection_summary`.

### Frontend (`frontend/src`)
- `components/FindingsPanel.tsx`: tarjetas de hallazgo con severidad (colores), MITRE, entidades, afirmaciones Hecho/Inferencia/Hipótesis etiquetadas y evidencia con `Log_ID` clickeable (filtra la tabla por ese Log_ID); filtro por severidad con contadores; texto obligatorio "No hay evidencia en los logs proporcionados." cuando no hay hallazgos.
- `components/CoveragePanel.tsx`: tabla de cobertura (regla → estado → hallazgos → motivo) con resumen y tiempo de ejecución.
- `App.tsx`/`api.ts`/`types.ts`: integración y tipos `Finding`, `CoverageEntry`, `DetectionSummary`, etc.

## Validación contra el Excel de ejemplo (715 filas, 6 cadenas)

- **Total: 37 hallazgos (rango 25–50 del plan), 24 reglas ejecutadas, 0 errores de cobertura, ~90 ms.**
- Cadena 1 (spray DC-01): AUTH-002 ×1 con 33 fallos absorbidos (AUTH-001 ×0), AUTH-003 del éxito de mgarcia (EVT-00123), AUTH-004 y PRIV-002 (4672, EVT-00126).
- Cadena 2 (RDP admin): AUTH-003/AUTH-005/AUTH-004 (EVT-00174–00188), LAT-001 anclado (EVT-00188 → EVT-00222/225/227/231/232/235), EXEC-001/002/007, LAT-002 share Finance, EXF-001 (salida externa, EVT-00235), PRIV-002 (EVT-00193).
- Cadena 3 (backup/Finance + vssadmin): EXEC-001 (EVT-00280), EXF-004 con las 16 lecturas (EVT-00284–00309), EXEC-004 **Crítico** (EVT-00314), LAT-002 (EVT-00315).
- Cadena 4 (Legal + exfiltración): EXEC-005/006 (7z, EVT-00428), EXF-002/EXF-003 con los 22 POSTs (~253 MB).
- Cadena 5 (persistencia helpdesk): AUTH-007 (logon + persistencia misma cuenta/host), PERS-001 (4698, EVT-00523), PERS-002 (7045, EVT-00524), PERS-003 (5 ejecuciones de `wuhelper.exe` cada 6 min), EXEC-006.
- Cadena 6 (web): WEB-001 (15 errores 404/500), WEB-002 (13 peticiones login/admin), WEB-003 **Crítico** (cmd=whoami + `cmd.exe /c whoami` bajo `IIS APPPOOL\DefaultAppPool`, EVT-00599), EXEC-002 (whoami en URL).
- Cuentas benignas (mruiz, jlopez, dtorres…) sin hallazgos propios; fallos internos aislados no disparan AUTH-002 (anti-ruido).

## Fase C — qué quedó hecho

### Backend (`backend/app/correlation/`)
- **`config.yaml`**: parámetros de la fase C sin señales del ejemplo hardcodeadas — ventana de correlación (90 min), scores base por severidad (20/45/65/85, PLAN 7.1), bandas (0–39/40–59/60–79/80–100), puntos por factor con **tope +30** (PLAN 7.2), bonus de incidente por fases observadas (+5/fase, tope +15), mapeo kill chain por prefijo de regla con orden canónico, patrones genéricos de cuenta privilegiada / activo crítico, clasificaciones de override permitidas.
- **`loader.py`**: carga y validación estricta del YAML (severidades completas, bandas coherentes, tipos); error rápido `CorrelationConfigError`; caché de lectura.
- **`scoring.py`**: `score_hallazgo = min(100, base + min(30, Σ factores))`. Invariante verificado por test: cada severidad sin factores cae exactamente en su banda. Factores: los etiquetados por la detección (`origen_publico`, `acceso_a_datos_sensibles`, `volumen_grande`, `explotacion_web`) + derivados en correlación (multi-host ≥3, persistencia por categoría, evasión/repetición por regla, contexto privilegiado por patrones/categoría, activo crítico por patrón de host). Cada factor aplicado queda con puntos y motivo. La severidad del SIEM no influye (PLAN 7.1).
- **`correlator.py`**: agrupación por identidad fuerte compartida (usuario, IP de origen o destino) **con** distancia temporal ≤ ventana. Políticas aplicadas:
  - **Compartir host nunca agrupa solo** (PLAN 6.4): genera relación cruzada "mismo activo: cadenas independientes" entre incidentes.
  - Los hallazgos de reglas con "objetivo masivo" (`non_linking_user_rules: [AUTH-002]`, configurable) no agrupan por usuario: en un spray las víctimas no son la identidad del actor; el actor se vincula por IP de origen. Sin esto, el spray fusionaba la cadena 1 con la de backupsvc y salían 5 cadenas.
  - Los destinos tipo share UNC (`\\servidor\recurso`) son entidad débil (como el host): no agrupan.
  - Fusiones por identidad con misma clave canónica pero valores crudos distintos (`CORP\userone` vs `userone`) quedan anotadas como "relación posible por alias (inferencia)" (PLAN 4.2).
  - Incidente (`I-001..` ordenado por tiempo): timeline de hallazgos con evidencia clickeable, activos/cuentas afectadas, **IoCs extraídos solo de los eventos de evidencia** (IPs públicas, dominios, URLs, archivos, shares, servicios/tareas, cuentas, hashes si existen), fases kill chain **solo observadas**, MITRE unido, `score_incidente = min(100, max(score_hallazgos) + 5×(fases−1))` con tope de bonus +15, banda coherente y justificación de agrupación (entidades compartidas + distancia máxima + notas de alias).
- **Integración**: `run_analysis` puntúa los hallazgos y corre la correlación al final de la detección; el resultado vive en `result.correlation` con `overrides` aparte en `AnalysisResult`.
- **API** (`api/routes_correlation.py`): `GET /api/sessions/{id}/incidents` (incidentes + relaciones + resumen, con overrides aplicados) y `POST /api/sessions/{id}/overrides` (`target_type` finding|incident, clasificación de la lista configurada, **motivo obligatorio**; valida que el objetivo exista; conserva el score automático, PLAN 7). El `GET /findings` existente también refleja el override del hallazgo.

### Frontend (`frontend/src`)
- `components/IncidentsPanel.tsx`: tarjetas de incidente con banda+score, fases kill chain observadas, MITRE, timeline con `Log_ID` clickeables (filtra la tabla), IoCs por tipo, activos/cuentas afectadas, justificación de agrupación con notas de alias (etiquetadas Inferencia), relaciones "mismo activo" al pie, y formulario de override (clasificación + motivo obligatorio, muestra el valor previo).
- `components/FindingsPanel.tsx`: badge de score/banda automática y badge de override manual con el motivo en el tooltip.
- `App.tsx`/`api.ts`/`types.ts`: integración, `getIncidents`, `createOverride` y tipos `Incident`, `OverrideInfo`, `CorrelationResponse`, etc.

## Validación fase C contra el Excel de ejemplo

- **6 cadenas exactas (I-001..I-006), 37 hallazgos repartidos, todos asignados a un incidente**, coinciden con las cadenas del PLAN §14:
  - I-001 spray DC-01: AUTH-002 + AUTH-003 (mgarcia) + AUTH-004 + PRIV-002 — agrupados por la IP de origen del actor.
  - I-002 RDP admin + lateral: 12 hallazgos (AUTH-003/005/004, LAT-001, PRIV-002, EXEC-001/002/007, LAT-002, EXEC-005/006, EXF-001) — agrupados por `CORP\admin` y orígenes.
  - I-003 backup/Finance + vssadmin: EXEC-001, EXF-004, EXEC-004, LAT-002 — por `CORP\backupsvc`.
  - I-004 Legal + exfiltración: LAT-002, EXEC-005/006, EXF-002/003 — por `CORP\rrojas`.
  - I-005 persistencia helpdesk: AUTH-007, EXEC-006 ×3, PERS-001/002/003 — por `CORP\helpdesk`.
  - I-006 web: EXEC-002 ×2, WEB-001/002/003 — por la IP de origen del atacante.
- 4 relaciones "mismo activo" entre cadenas independientes que comparten FS-SRV01 / APP-SRV01, sin fusionarse.
- Scores de incidente: 85–100, banda Crítica coherente; override de prueba registrado y reflejado conservando el score automático.
- Suite: **77 tests verdes** (58 previos + 19 de correlación: invariantes de scoring, tope de factores, no-agrupación por host, ventana temporal, nota de alias, fases solo observadas, IoCs, 6 cadenas, override y validaciones).

## Decisiones tomadas (fase C)

- El YAML de correlación es un archivo aparte (`correlation/config.yaml`) con validación propia; igual filosofía que las reglas: parámetros auditables, sin señales del ejemplo en código.
- "Identidad fuerte" para agrupar: usuario (clave canónica sin dominio), IP de origen y destino (host/IP). Host y share UNC son débiles: solo generan relación "mismo activo". El PLAN exige no agrupar por servidor compartido y las cadenas 2/3/4 del ejemplo comparten FS-SRV01 con cuentas distintas.
- AUTH-002 no agrupa por usuario (`non_linking_user_rules`): sus usuarios son el objetivo masivo del spray; sin esta regla el ejemplo daba 5 cadenas en vez de 6.
- La fase kill chain se asigna por prefijo de regla (AUTH/WEB→Acceso inicial, PRIV→Escalada, EXEC→Ejecución, PERS→Persistencia, LAT→Movimiento lateral, EXF→Exfiltración); solo se muestran fases con hallazgo observado.
- La distancia temporal entre hallazgos usa la separación entre rangos [start,end] (solapamiento cuenta como 0 min); la ventana por defecto es 90 min configurable en el YAML.
- Los IoCs se extraen únicamente de los eventos citados como evidencia (campos normalizados: IPs públicas, URLs, rutas, shares, tarea/servicio, cuentas, hashes si existieran), nunca de texto inventado.
- El override manual se guarda en memoria junto a la sesión (sin persistencia en disco; la sesión ya es en memoria según el PLAN). Clasificaciones permitidas configurables: Crítico/Alto/Medio/Bajo/Falso positivo.

## Decisiones tomadas (fase B)

- La detección es **100% determinista**: YAML + Python; sin IA, sin hardcodear IPs/usuarios/hostnames del ejemplo; los patrones (`svc`, `finance`, `legal`, códigos, umbrales) son parámetros del YAML.
- El score numérico de hallazgos/incidentes y el override manual quedan para la fase C (PLAN 7); aquí los hallazgos llevan `base_severity` de la regla.
- `LAT-004` queda con cobertura `insufficient_data` (requiere línea base histórica; fase H), igual que AUTH-006/AUTH-008/BASE-001/BASE-002 (sin implementar aún).
- Clasificación de IPs: RFC1918 = private; rangos de documentación (usados en logs sintéticos como "IPs externas") = public; decisión documentada en `validate_ip`.
- Absorción de spraying: los fallos de las víctimas entran en `absorbed_detail` del AUTH-002 y se excluyen de AUTH-001; el evento de éxito correspondiente genera su AUTH-003 aparte.
- Los eventos de servicio (7036) y logoffs (4634) no se tratan como logons para las reglas de autenticación.

## Fase D — qué quedó hecho

### Backend
- **`services/stats.py`**: agregados deterministas para el dashboard, calculados desde `result.events` + `detection` + `correlation` ya en memoria (sin segunda pasada sobre el Excel ni IA):
  - KPIs: eventos totales y con timestamp válido, hallazgos por severidad, incidentes por banda, usuarios/hosts/IPs afectadas, reglas ejecutadas/omitidas/error, overrides manuales y alertas de calidad (timestamps inválidos/faltantes, IPs inválidas, Log_ID sintéticos, duplicados, tipos mezclados), rango temporal.
  - `events_timeline`: buckets por hora (o por día si el rango supera 192 horas; regla determinista), con `granularity` declarada.
  - `top`: top-N (10 por defecto, `top_n` configurable 1–50) de IPs origen, usuarios, hosts, Event_ID, origen de log y severidades SIEM; orden determinista (conteo desc, valor asc en empates).
  - `siem_vs_calculated`: categorías de severidad en orden canónico del PLAN 7.1 (Crítico/Alto/Medio/Bajo, extras alfabéticos) con dos series: eventos por `severity_siem` y hallazgos por severidad calculada. Unidades distintas y marcadas como tales en la UI.
  - `heatmap`: matriz día × hora (0–23) de eventos.
  - `mitre`: conteo de técnicas citadas en los hallazgos.
- **`api/routes_dashboard.py`**: `GET /api/sessions/{id}/stats` (404 si no hay sesión o no hay análisis, mensajes en español). Registrado en `main.py`; health y versión ahora fase D.
- **Filtro temporal en `GET /api/sessions/{id}/events`**: parámetros `time_from`/`time_to` (ISO 8601, inclusivos, se comparan como hora de pared según PLAN 4.3; inválidos → 400). Los eventos sin timestamp válido quedan fuera del resultado filtrado. Es el soporte del drill-down desde timeline y heatmap.

### Frontend (`frontend/src`)
- **`App.tsx`**: navegación por pestañas en el paso de análisis: Dashboard · Incidentes · Hallazgos · Cobertura · Eventos · Calidad · Alias (antes todo apilado en vertical). Los drill-downs del dashboard cambian de pestaña y aplican el filtro. Los filtros de hallazgos (severidad + búsqueda) viven ahora en App para que el dashboard pueda accionarlos.
- **`components/DashboardPanel.tsx`** (nuevo, Recharts ya estaba en `package.json`, sin dependencias nuevas):
  - 8 KPIs (las tarjetas de Incidentes/Reglas/Calidad navegan a su pestaña).
  - Hallazgos por criticidad (clic → hallazgos filtrados por severidad) e incidentes por banda (clic → pestaña Incidentes).
  - Timeline de eventos por bucket (clic → tabla filtrada a ese rango temporal con chip visible y botón para quitarlo).
  - Severidad SIEM vs calculada (dos series: clic en SIEM filtra eventos por `severity_siem`; clic en calculada filtra hallazgos).
  - Tops de IPs/usuarios/hosts, Event_ID y origen de log (clic → tabla filtrada por esa columna) y MITRE (clic → hallazgos con búsqueda por técnica). Etiquetas del eje siempre visibles (`interval={0}` + alto proporcional a las entradas) y valores largos acortados en el eje con el valor completo en el tooltip.
  - Heatmap hora × día como tabla CSS accesible (número en cada celda + tooltip + `aria-label`); celda vacía sin color; clic filtra esa hora.
- **`EventsTable.tsx`**: `TableQuery` con `timeFrom`/`timeTo`, chip de rango temporal con botón para quitarlo.
- **`FindingsPanel.tsx`**: filtros elevados a props controladas + campo de búsqueda (regla, MITRE, entidad).
- **`api.ts`/`types.ts`**: `getStats`, `time_from`/`time_to` en `getEvents`, `q` en `getFindings`, tipos `DashboardStats`/`StatEntry`.

## Validación fase D contra el Excel de ejemplo (10 tests nuevos)

- Coherencia total con el motor: la suma de `findings_by_severity` == `total_findings` == `detection_summary.total_findings`; la suma de `incidents_by_band` == `total_incidents`; la suma del timeline y del heatmap == eventos con timestamp válido.
- Tops ordenados por conteo descendente y acotados a `top_n`; MITRE derivado íntegramente de los hallazgos.
- Determinismo: dos llamadas consecutivas a `/stats` devuelven JSON idéntico.
- Drill-down temporal verificado: filtrar eventos por `time_from` del bucket más poblado devuelve >0 filas, todas con `timestamp_parsed` dentro del rango, y ≤ total con timestamp.
- `test_health` actualizado a fase D; 404 para sesión inexistente y para sesión sin análisis.

## Decisiones tomadas (fase D)

- El dashboard no recalcula nada en el cliente: un único endpoint `/stats` agrega desde los eventos ya normalizados y los resultados del motor; así UI y API comparten exactamente las mismas cifras.
- La granularidad del timeline cambia de horas a días con una regla fija (>192 horas de rango), declarada en la respuesta (`granularity`); el frontend no adivina.
- El drill-down temporal usa `time_from`/`time_to` sobre `timestamp_parsed` comparado como hora de pared (sin conversión de zona horaria, PLAN 4.3); los eventos sin timestamp válido quedan fuera del filtro y así se documenta en el código.
- Severidad SIEM vs calculada se muestra como dos series separadas (eventos vs hallazgos), nunca como "corrección" de una sobre otra: la severidad del SIEM no influye en el score (PLAN 7.1).
- El heatmap se hace con tabla HTML en vez de un gráfico de Recharts: control total de accesibilidad (número visible, tooltip, aria-label) y sin librería extra.
- La navegación por pestañas sustituye el apilado vertical del paso 3: es la "navegación" del criterio de la fase y reduce el scroll con los 7 paneles existentes.

## Fase E — qué quedó hecho

### Backend
- **`reporting/templates.py`** (plantillas deterministas): redacción completa **sin IA** a partir de los hallazgos e incidentes ya estructurados — resumen ejecutivo (eventos, hallazgos por severidad, incidentes top, calidad de timestamps), textos por hallazgo (regla, severidad/score, afirmaciones Hecho/Inferencia/Hipótesis de la detección, entidades observadas, absorbed_detail, MITRE) y por incidente (banda/score, fases kill chain observadas, timeline, IoCs de la evidencia, notas de alias como Inferencia). Si un hallazgo no tiene evidencia, usa la frase exacta obligatoria: **"No hay evidencia en los logs proporcionados."**
- **`ai/settings.py`**: `AI_PROVIDER` (none | gemini | anthropic | openai_compatible | ollama), `AI_MODEL`, `AI_BASE_URL`, `AI_API_KEY`, `AI_TEMPERATURE` leídos del `.env` en cada llamada (testeable con monkeypatch). Proveedor **efectivo**: sin modelo, o sin clave en los proveedores cloud, cae a `none` → plantillas. Ollama es local (base por defecto `http://127.0.0.1:11434`).
- **`ai/providers/`** (adaptadores REST con `httpx`, sin SDKs): `openai_compatible` (`/v1/chat/completions`, Bearer), `anthropic` (`/v1/messages`, `x-api-key`), `gemini` (`generateContent`, clave en cabecera `x-goog-api-key`, nunca en URL) y `ollama` (`/api/chat`). Cada uno con `generate()` (JSON del LLM) y `test_connection()` (ping barato). Errores → `AIProviderError` con mensaje claro en español.
- **`ai/masking.py`**: enmascaramiento **reversible** para los proveedores cloud (usuarios, hosts, IPs, destinos, URLs/shares/rutas → `[USUARIO_1]`, `[IP_1]`…); los `Log_ID` y timestamps no se enmascaran para que el LLM pueda citar evidencia real. Ollama sin enmascaramiento por defecto (PLAN §10). Restaurado antes de validar.
- **`ai/validator.py`** (anti-alucinación, independiente del proveedor): el LLM responde JSON `{"paragraphs": [{section, label, text, citations}]}` y el backend valida por sección: (1) cada cita debe existir en los logs cargados **y** pertenecer a la evidencia de esa sección; (2) IPs, URLs y horas mencionadas deben existir en la evidencia; (3) cualquier entidad del caso mencionada fuera de la evidencia de la sección → rechazo; (4) cifras de ≥3 dígitos deben ser verificables en la evidencia o ser totales derivados de la propia sección (los conteos de 1–2 dígitos se toleran como lenguaje natural); (5) etiqueta limitada a Hecho/Inferencia/Hipótesis. JSON inválido → todo descartado. Cada rechazo registra su motivo y la sección cae a su plantilla.
- **`ai/service.py`**: orquestador `generate_narrative()`. Con `none` → solo plantillas. Con IA: construye el contexto por sección (evidencia + entidades + cifras permitidas), envía **solo datos estructurados** (afirmaciones, entidades, filas de evidencia recortadas, sin prompts libres), temperatura baja desde `.env`, valida y sustituye por plantilla lo rechazado; `ai_state` registra used/accepted/rejected/error/masking.
- **`api/routes_ai.py`**: `GET /api/ai/settings` (vista pública: nunca incluye la clave, solo `key_configured`), `POST /api/ai/test` (prueba de conexión; con `none` informa que se trabaja por plantillas), `POST /api/sessions/{id}/narrative` (genera y almacena en la sesión en memoria) y `GET .../narrative`. `main.py` registra el router y health pasa a fase E.

### Frontend (`frontend/src`)
- **Pestaña nueva "Redacción"** (`components/NarrativePanel.tsx`): tarjeta de ajustes IA (proveedor, modelo, estado de la clave —configurada/no configurada, nunca su valor—, temperatura, base URL si aplica) con botón **Probar conexión**; botón Generar/Regenerar redacción; secciones plegables (resumen ejecutivo, cada hallazgo, cada incidente); cada párrafo con chip de etiqueta (Hecho/Inferencia/Hipótesis) y chip de origen (`plantilla` / `IA validada`); citas `Log_ID` clickeables (abren la fila cruda en Eventos); panel de validación con párrafos aceptados/descartados y sus motivos cuando se usa IA.
- `api.ts`/`types.ts`: `getAiSettings`, `testAiConnection`, `generateNarrative`, `getNarrative` y tipos asociados.

## Validación fase E (25 tests nuevos; suite completa: 112 verdes)

- Ajustes: por defecto `none`/plantillas; con clave configurada `key_configured=True` y el valor del secreto **nunca** aparece en la respuesta; cloud sin clave o sin modelo → modo plantillas.
- Prueba de conexión: `none` → ok con mensaje de plantillas; cloud sin clave → informa plantillas (sin llamadas).
- Adaptadores con `httpx.MockTransport` (sin llamadas reales): openai_compatible, anthropic, gemini y ollama devuelven el texto esperado; HTTP 401 → `AIProviderError` con mensaje claro; proveedor desconocido → error.
- Enmascaramiento reversible roundtrip; los `Log_ID` sobreviven al enmascaramiento; `mask_payload` recursivo.
- Validador: acepta un párrafo correcto; rechaza cita inexistente, cita fuera de la evidencia de la sección, IP inventada, entidad del caso de otra sección, cifra de ≥3 dígitos no verificable, párrafo sin citas y JSON inválido (con motivo registrado).
- Plantillas: hallazgo sin evidencia → frase exacta obligatoria.
- End-to-end con el Excel de ejemplo (`AI_PROVIDER=none`): 44 secciones (resumen + 37 hallazgos + 6 incidentes), 231 párrafos, todos `source=plantilla`, `ai_state.used=False`, y cada párrafo de hallazgo cita solo `Log_ID` de su propia evidencia.
- IA simulada: respuesta no-JSON → todo cae a plantilla con motivo; respuesta con 1 párrafo válido + 1 inventado → 1 aceptado (`ia_validada`), 1 rechazado, y el resto de secciones conservan la plantilla.
- Prueba de humo contra la API viva: análisis (715 filas) → `POST /narrative` → modo plantillas, citas reales (p. ej. spray con `EVT-00057…`), sesión de prueba eliminada.

## Decisiones tomadas (fase E)

- El chat de IA se pospone a F2 (PLAN §12): la fase E solo **redacta** secciones del informe; la IA no participa en detección, correlación ni scoring.
- El validador es independiente del proveedor y valida contra la **evidencia de cada sección**, no contra el caso entero: esto evita el "dato real pero fuera de contexto" (mencionar la víctima de otra cadena en un hallazgo donde no aparece).
- La tolerancia de cifras de 1–2 dígitos es deliberada (permiten lenguaje natural tipo "2 eventos"); toda cifra de ≥3 dígitos debe existir en la evidencia o ser un total derivado del hallazgo/incidente (score, nº de eventos, etc.).
- Enmascaramiento reversible mantenido solo en memoria durante la petición; nunca se persiste el mapa ni se envían valores reales a proveedores cloud.
- La redacción se guarda en la sesión en memoria (`AnalysisResult.narrative`); regenerar la sobrescribe. Sin persistencia en disco (coherente con el resto del análisis).
- Los adaptadores no registran la clave ni el cuerpo completo de las peticiones en el log; los errores se reportan con mensajes genéricos en español.
- `.env.example` ya documentaba `AI_*` (fase 0); no hizo falta añadir variables nuevas.

## Ajustes de IA desde la UI (post-F)

Decisión del desarrollador (documentada como desviación puntual del PLAN §10): la clave de IA **no** se introduce por `.env`, sino por la UI, y vive **solo en memoria del backend** — nunca se persiste en disco ni en el repo, nunca se devuelve por la API y se pierde al reiniciar `start.ps1`.

### Backend
- **`ai/settings.py`**: override en RAM con lock (`set_runtime_settings`, `clear_runtime_key`, `clear_runtime_settings`, `runtime_is_active`) y validación estricta (proveedor de la lista, temperatura 0–2, límites de longitud; `SettingsError` → HTTP 400). `load_ai_settings()` fusiona: **override de la UI > `.env`**.
- **`api/routes_ai.py`**: `POST /api/ai/settings` (guarda ajustes; `api_key` vacía = conservar la actual; `clear_key: true` = borra la clave de RAM y cae a la del `.env` si existiera), `DELETE /api/ai/settings` (restablece todo al `.env`). `GET /api/ai/settings` añade `settings_source: "ui" | "env"`. La clave jamás aparece en ninguna respuesta (solo `key_configured`).
- Fix cosmético heredado de la fase E: `get_adapter` ahora fija `adapter.name` (el campo dataclass `name` de `BaseAdapter` ignoraba el atributo de clase de cada adaptador y los errores decían `proveedor ''`).

### Frontend
- La tarjeta "Ajustes de IA" de la pestaña **Redacción** ahora es editable: proveedor (desplegable), modelo, base URL (solo para `openai_compatible`/`ollama`), temperatura y clave (campo tipo password, placeholder "sin cambios" si ya hay una). Botones: **Configurar / Guardar ajustes / Probar conexión / Borrar clave / Restablecer (.env)**; badge "ajustes de esta sesión (UI)" cuando hay override.

### Validación (8 tests nuevos; suite completa: 138 verdes)
- POST activa IA en RAM (`mode: ia`, `settings_source: ui`) y la clave **no** aparece en ninguna respuesta; clave vacía en segunda pasada conserva la anterior; `clear_key` cae a la clave del `.env` (o a "no configurada"); `DELETE` vuelve al `.env`; validaciones 400 (proveedor inválido, temperatura fuera de rango); garantía de no-persistencia (el `.env` no cambia tras guardar ajustes); la redacción usa los ajustes de RAM (adaptador simulado; respuesta inválida del LLM cae a plantillas).

### Ajustes posteriores (misma sesión, con la suite en 144 verdes)
- **Parser robusto de la respuesta del LLM** (`ai/validator.py`): los LLM reales a menudo envuelven el JSON en vallas ```json con texto introductorio/final o cortan la respuesta; `parse_llm_payload` ahora tolera vallas en cualquier posición, extrae el objeto más externo y, si el JSON está truncado, reporta el motivo concreto ("parece truncada… sube AI_MAX_OUTPUT_TOKENS"). El motivo de rechazo del validador incluye el detalle del error (antes solo el tipo de excepción). +6 tests (directo, vallas, vallas con texto alrededor, JSON con texto sin vallas, truncado, falta `paragraphs`).
- **`AI_MAX_OUTPUT_TOKENS` por defecto 2000 → 4000** (`ai/settings.py`): con 44 secciones en una sola llamada, 2000 tokens truncaba el JSON y caía todo a plantillas.
- **Selector cualitativo de temperatura en la UI** (`NarrativePanel.tsx`): el campo numérico se sustituye por un desplegable con perfiles — *Muy precisa (0), Precisa — recomendada (0.1), Equilibrada (0.3), Creativa (0.7), Muy creativa (1), Personalizada…* (solo si elige "Personalizada" aparece el campo numérico 0–2). En modo vista se muestra el perfil ("Precisa (0.1)"), no el número crudo. Sin cambios de API.
- **Aviso operativo**: los ajustes de IA viven en RAM; editar código del backend (con `--reload`) o reiniciar `start.ps1` los borra y hay que volver a pegar la clave en la UI. Es la contrapartida de "sin secretos en disco".

### Depuracion con IA real contra OpenRouter (misma sesion, suite en 146 verdes)

El primer intento end-to-end del usuario con OpenRouter revelo una cadena de problemas reales que las pruebas con adaptadores simulados no podian detectar:

1. **Respuesta del LLM no parseable**: los modelos envuelven el JSON en vallas ```json con texto alrededor; el parser solo lo toleraba si el texto empezaba/terminaba exactamente en las vallas. -> `parse_llm_payload` ahora tolera vallas en cualquier posicion, extrae el objeto mas externo y distingue JSON truncado (con motivo concreto). El motivo de rechazo incluye el detalle de la excepcion.
2. **Modelo con razonamiento (`z-ai/glm-5.3-flash`)**: via OpenRouter el razonamiento es obligatorio para ese endpoint (`reasoning: {"enabled": false}` -> HTTP 400 "Reasoning is mandatory"); y con el payload completo (45k tokens de entrada) el razonamiento consume TODO el presupuesto (30k tokens, 8 minutos) dejando `content` vacio. -> Se quito el parametro, se subio `AI_MAX_OUTPUT_TOKENS` a 6000 y el adaptador ahora: elimina bloques `<think >...` incrustados y da error claro y especifico si `content` llega vacio con `reasoning` presente. Conclusion documentada: **para este flujo se necesita un modelo de chat sin razonamiento** (p. ej. `openai/gpt-4o-mini`); los modelos tipo razonador se obsesionan con payloads grandes.
3. **Bugs de integracion fase E (solo visibles con IA real)**: `context_from_pool` leia `user_raw/host_raw/source_ip/timestamp_parsed` pero las filas de `_evidence_rows` usan claves en espanol (`usuario/host/ip_origen/timestamp`) -> el pool de entidades y horas de cada seccion estaba VACIO y el validador rechazaba toda entidad/hora real. -> Ahora acepta ambos juegos de claves (+2 tests de regresion).
4. **Cumplimiento del modelo**: el LLM no rellenaba `citations` y reutilizaba entidades entre secciones. -> El payload ahora entrega por seccion `citas_permitidas`, `citations_sugeridas` y `entidades_permitidas` explicitas, y el system prompt exige copiar 1-3 IDs literales de esa seccion (nunca citations vacio).
5. **Timeout**: la llamada real tarda 60-90s; el timeout por defecto 30s la cortaba. -> `AI_TIMEOUT_SECONDS` por defecto ahora 180.

**Resultado final verificado end-to-end via la API viva** (OpenRouter + `openai/gpt-4o-mini`, enmascaramiento activo): `mode: ia`, **32 parrafos "IA validada"** de 38 solicitados; los 6 rechazados (hora mal citada, IPs de otra seccion, cita cruzada, cifra no verificable) cayeron a plantilla determinista — el validador anti-alucinacion trabajando como esta diseñado.

### Layout del PDF optimizado (misma sesion, suite en 147 verdes)
- Antes cada seccion forzaba pagina nueva: con 58 secciones el informe tenia ~84 paginas y los hallazgos dejaban media pagina en blanco. Ahora **solo las secciones "capitulo"** (portada, resumen, metodologia, tabla resumen, evidencias, timeline/MITRE, criticidad, impacto, plan de accion, IoCs, recomendaciones, limitaciones y anexos) fuerzan pagina nueva; **los hallazgos e incidentes fluyen uno debajo del otro** con subtitulo compacto. Ademas: los parrafos no se parten entre paginas (`break-inside: avoid`), los titulos no quedan huerfanos al pie (`break-after: avoid`) y las cabeceras de tablas largas se repiten en cada pagina (`thead: table-header-group`). Resultado: **84 -> 55 paginas (-34%)** con el mismo contenido, verificado via API viva y con test de regresion que cuenta los saltos (1 tras la portada + 1 por capitulo, cero por hallazgo/incidente).

### Informe jerarquico e indice clicable (misma sesion, suite en 148 verdes)
- **Estructura jerarquica** (`reporting/report.py`): "5. Hallazgos" e "6. Incidentes" son ahora **capitulos contenedor** (kind `contenedor`, no editables, con parrafo introductorio) y cada hallazgo/incidente es un **subpunto** (`5.1`, `5.2`…, `6.1`…, con `parent` y `level` en cada seccion). Los `section_id` se mantienen estables (`hallazgo:F-001`), por lo que las ediciones/regeneraciones del analista siguen funcionando; editar o regenerar un contenedor devuelve 400. Numeracion jerarquica ("5", "5.1") en API, UI y PDF.
- **Indice clicable** (`reporting/pdf.py`): cada seccion lleva un `id` HTML estable (`sec-hallazgo-F-001`, con `:` normalizado) y el indice son enlaces `<a href="#...">`; **Chromium los convierte en anotaciones `/Subtype /Link` con destino interno en el PDF** (verificado: 60 enlaces). Sin dependencias nuevas. El indice muestra la jerarquia (subpuntos indentados).
- **Flujo compacto por bloques (Opcion C)**: solo los capitulos (nivel 1) fuerzan pagina; cada hallazgo/incidente es un bloque fluido con `break-inside: avoid` (no se parte entre paginas). 57 paginas frente a las ~84 originales.
- **Frontend** (`ReportPanel.tsx`): arbol anidado (contenedor -> subpuntos con estilo propio), cabecera compartida, boton Editar solo en secciones editables, filtro por capitulo o subpunto.
- Tests: jerarquia (parent/level/numeracion/contenedores no editables), indice clicable (hrefs == anchors), `/Link` presente en el PDF real, edicion de contenedor -> 400.

## Pulido de presentación del informe (post-F2)

Ciclo completo de presentación del informe/PDF tras revisión A/B/C del desarrollador (diseño, jerga fuera y cambios de contenido). **Sin cambios de detección ni scoring** (la duda I-005 se mostró al desarrollador y queda a su decisión).

### Contenido (`reporting/report.py`, reescrito)
- **Portada dentro del PDF**, ya no como sección del informe: título, nombre real del archivo, cliente/analista editables, fecha de generación (dd/mm/aaaa hh:mm) y clasificación "Confidencial – Uso interno". Sin tabla duplicada de "datos del caso".
- **Resumen ejecutivo de 1 página**: 4 tarjetas KPI (eventos, hallazgos, incidentes, banda máxima), donut SVG de hallazgos por banda final, y 1 párrafo por incidente con citas `Log_ID`.
- **Hallazgos como tarjetas** (capítulo con 2 columnas CSS): cada hallazgo con banda final (score tras factores/bonus, nunca la severidad base), meta (banda/score/regla/eventos/Log_IDs), entidades y afirmaciones etiquetadas. Capítulo con barras MITRE SVG.
- **Incidentes**: portadilla por incidente con cronología SVG de línea temporal, fases kill chain observadas, IoCs retipeados y activos.
- **Plan de acción por incidente** (cambio C del checklist): tabla Investigar/Contener/Remediar con prioridad, owner y SLA por fase — editable por el analista como el resto.
- **Títulos descriptivos de incidentes** (`correlation/correlator.py`): "entidad anómala + actividad + anclaje" (p. ej. "Cuenta de servicio/helpdesk interactiva u origen raro - APP-SRV01"); nunca el patrón viejo "Cadena de N hallazgo(s)…".
- **IoCs re-categorizados**: hosts/rutas/cuentas/servicios_tareas (sin "-" ni vacíos); etiquetas en español en API, CSV y UI.
- **Jerga eliminada**: estados de cobertura en español (Ejecutada / Ejecutada sin hallazgos / Datos insuficientes / Omitida por campos faltantes) en informe, coverage UI y CSV; "lat_004" renombrado en `detection/impl/lateral.py`; sin "fase H"/"PLAN 4.3" en textos del informe.
- **Anexos A–D** (antes numerados): calidad, cobertura, evidencias deduplicadas (una fila por `Log_ID` con el texto literal completo) y alias.
- **Meta de portada editable**: campo `report_meta` en `AnalysisResult` + `PUT /api/sessions/{id}/report/meta` (cliente/analista).

### Diseño (`reporting/pdf.py`, reescrito; `reporting/charts.py` nuevo)
- **Chips de severidad con color Y texto** (Crítico rojo / Alto naranja / Medio amarillo / Bajo verde), clases CSS `critico/alto/medio/bajo`.
- **Gráficos SVG puros** (`charts.py`): donut de bandas, cronología por incidente, barras MITRE — sin librerías nuevas.
- **Tablas**: anchos de columna fijos (`colgroup`), columnas monoespaciadas para IDs/LOG_IDs (`keep-all`), formato corto de tiempo dd/mm hh:mm:ss, cabecera repetida en cada página y filas sin cortar (`break-inside: avoid`).
- **Los gráficos SVG puros y los chips** están listados en la sección de diseño.
- **Anexos en horizontal** (`@page apaisada`) con `prefer_css_page_size`.
- **Solo 5 saltos forzados**: tras portada, tras índice (antes del resumen), antes de hallazgos y antes de anexos; hallazgos a 2 columnas dentro del capítulo, flujo continuo en el resto.
- **Índice clicable a 2 niveles con números de página** (2 pasadas de Chromium): la 1.ª renderiza y extrae las páginas reales por named destinations; la 2.ª inserta el número. Los hallazgos NO se listan individualmente (solo capítulos + subpuntos de incidentes).
- Tipografía única (una familia), texto alineado a la izquierda, tildes correctas en todos los títulos.

### Frontend (misma sesión)
- `ReportPanel.tsx`: portada editable (cliente/analista, botón "Guardar portada"), mínimo de secciones con `kind resumen/plan/hallazgo/incidente/contenedor`, tarjetas y meta visibles, nota de qué incluye el PDF.
- `IncidentsPanel.tsx`/`api.ts`/`types.ts`: etiquetas IoC nuevas en español.
- `api.ts`/`types.ts`: `saveReportMeta` (PUT /report/meta), `file_name`/`meta`/`band_colors`/`cards`/`charts`/`landscape`/`break_before` en los tipos.

### Validación verificación PDF (API viva, mismo día)
- `data/exports/informe_verificacion_manual.pdf`: **25 páginas** con el Excel de ejemplo (antes ~30): portada, índice clicable (126 enlaces), KPIs+donut, hallazgos en tarjetas 2-col, incidentes con cronología SVG, plan de acción, IoCs y anexos A–D (evidencias y alias en horizontal).
- Suite: **149 tests verdes** (+1 nuevo `test_report_polish_requirements`: bandas finales, jerga fuera, KPIs/donut, plan Investigar/Contener/Remediar, cobertura en español, meta de portada, anexo deduplicado landscape). Los tests de informe re-escritos a la estructura jerárquica nueva (anexos A–D, capítulos 4/5, hallazgos e incidentes a subpuntos).

### Pulido 2 de presentación (misma sesión; suite en 150 verdes)

Correcciones a partir del PDF de referencia del desarrollador (`informe_Cuarta_Version.pdf`), solo presentación/plantillas — sin cambios de detección ni scoring:

- **HTML crudo fuera de los párrafos (bug crítico)**: `_render_para` devolvía `str` y Jinja2 con autoescape lo escapaba → TODOS los párrafos del PDF se veían como `<p class="para"><span class="lbl lbl-Hecho">…`. Ahora devuelve `Markup` (regresión cubierta por test: el HTML renderizado no contiene `&lt;p` y sí contiene el elemento real).
- **"Espacio para logo" eliminado** (A11): sin caja ni CSS de logo; la clasificación ocupa la cabecera de la portada.
- **Resumen ejecutivo a 1 página con 1 párrafo de 3 frases por incidente (A2)**: antes, si existía redacción IA/plantilla del capítulo, sustituía los blurbs y el resumen quedaba con un solo párrafo. Ahora la redacción del capítulo va de intro y los blurbs por incidente están SIEMPRE presentes (citas deduplicadas de la evidencia del propio incidente; test verifica ≥3 frases y citas ∈ evidencia del incidente).
- **Títulos de incidente por config (C)**: nuevo bloque `incident_titles.phrases` en `correlation/config.yaml` (frase genérica por regla ancla, editable, sin señales del ejemplo; con frase la usa el título, sin ella el nombre de la regla). Resultado en el ejemplo: "Password spraying y toma de cuenta en DC-01", "Borrado de copias de sombra en WS-023", "Exfiltración por envíos web masivos en WS-018", etc. `CorrelationConfig` carga y valida el bloque.
- **IoCs (C)**: las rutas UNC de share (`\\FS-SRV01\Finance`) ya no se listan como Hosts (van solo a Shares SMB con el valor completo); sin vacíos ni "-" (test en la suite de correlación).
- **Citas deduplicadas**: las listas de Log_ID por párrafo ya no repiten IDs (Impacto y demás; test de regresión).
- **Volumen legible**: bytes_out con separador de miles y equivalente MB ("506.611.116 bytes (≈483,4 MB)").
- **Anexo D sin filas vacías**: las relaciones de alias sin clave canónica ni valores observados ya no se listan ("Cuentas — sí" en la Cuarta Versión).
- **Dona verificada por código** (artefacto de extracción de texto causaba duda): leyenda correcta por banda final — en el ejemplo 12 Crítico / 12 Alto / 13 Medio (37 hallazgos); test añade la comprobación de la leyenda contra los conteos reales.
- PDF de verificación regenerado (modo plantilla, sin IA): **25 páginas** (`data/exports/informe_verificacion_manual.pdf`), 126 enlaces de índice, sin jerga, sin HTML crudo, sin "logo"; el resumen ocupa exactamente la página 3.

### Pulido 3: footer solapado y cronologias con marcas ocultas (misma sesión; suite en 151 verdes)

A partir de la Quinta Versión del desarrollador (`informe_Quinta_Version.pdf`, 23 págs):

- **Footer superpuesto al contenido (bug de impresión)**: el CSS declaraba `@page { margin: 0 }` y **el margen de la CSS gana sobre el de Playwright** → el pie de Chromium ("Página X de Y") se imprimía dentro de la franja del contenido y el texto/la gráfica del resumen lo pisaban. Ahora el CSS lleva márgenes reales (`10mm arriba / 14mm abajo`, también en horizontal) y Playwright usa los mismos valores: el contenido nunca entra en la banda del pie. La portada deja de usar `height: 96vh` (no fiable con márgenes reales).
- **Puntos invisibles en las cronologías**: varios hallazgos del mismo incidente comparten el instante exacto (p. ej. las ejecuciones encadenadas de PERS-003) y los círculos se dibujaban superpuestos en la misma coordenada. Ahora `incident_timeline_svg` **apila** las marcas coincidentes con desfase vertical determinista (0, ±10, ±20 px) y muestra un contador **"×N"** sobre cada grupo; el `viewBox` crece (66→88) y el tooltip incluye el Log_ID, la regla y la hora. Test de regresión: 3 círculos, offsets distintos y badge.
- **Compensación de densidad (solo CSS)**: espaciados de párrafos/tarjetas/tablas/KPIs ligeramente más compactos para absorber la altura perdida por los márgenes ("150" → "151" tests no afectados).
- Impacto en páginas: 23 (Quinta Versión, con solapamiento) -> **26 sin solapamiento**. El recorte hacia el objetivo 15–20 sigue abierto: requiere decidir en anexos (evidencia completa es ~6 págs en horizontal).

### Pulido 3b: dona con leyenda recortada y titulo pisado (misma sesión; suite en 151 verdes)

Captura del desarrollador del resumen ejecutivo: la leyenda mostraba "1 / 1 / 1" y el título quedaba detrás del aro.

- **Leyenda recortada (causa geométrica)**: la columna de cifras la ancla `text-anchor="end"` en x=340 **fuera del viewBox (ancho 330)** → Chromium recortaba el último dígito ("12"→"1", "13"→"1"). Ahora la cifra termina en x=320 y el viewBox es 350 de ancho. Leyenda verificada visualmente (render a PNG): 12 Crítico / 12 Alto / 13 Medio.
- **Título pisado por el aro**: el círculo (top y=12) invadía la línea del título (baseline y=18); el aro baja a cy=100 (top y=22) y el título sube a y=16.
- Verificación visual de las 3 gráficas (dona, barras MITRE, cronologías) con captura PNG standalone antes de regenerar el PDF: colores correctos por banda, barras con técnica+conteo, cronologías con marcas apiladas y badges ×N.
- `data/exports/informe_verificacion_manual.pdf` regenerado: 26 páginas, 126 enlaces, suite 151 verdes.

### Pulido 3c: chip "Hecho" fuera de los párrafos (misma sesión; suite en 151 verdes)

Petición del desarrollador: cada párrafo arrancaba con la palabra "Hecho" (chip de marca de afirmación).

- Causa: `_render_para` renderizaba siempre el chip de etiqueta; toda la plantilla usa "Hecho" por defecto → 119 párrafos con la misma palabra al inicio.
- Ahora el chip **"Hecho" no se renderiza** (es la marca por defecto: la ausencia de chip ya lo comunica). Los chips **Inferencia** e **Hipótesis** se mantienen porque sí cambian la lectura del afirmación (regla del plan n.º 4 intacta).
- La estructura de datos de párrafos (`label` en los dicts) no cambia: la IA y el validador siguen usando Hecho/Inferencia/Hipótesis; es solo presentación.
- Regresión en `test_pdf_html_contains_required_parts`: sin `>Hecho</span>` y con Inferencia/Hipótesis presentes.
- PDF regenerado en modo plantilla: 26 páginas, 126 enlaces, 321 KB (antes 345 KB).

### Decisiones de este pulido
- La IA (OpenRouter `openai/gpt-4o-mini`) solo redacta y pasa por el validador anti-alucinación; el PDF queda con plantilla si la IA no está configurada.
- **Página objetivo 15–20**: actual 26 (la Quinta Versión tenía 23 pero pisaba el footer) — los anexos (evidencias y alias) ocupan ~6 páginas con los textos literales completos; si hay que recortar, los anexos son el único sitio (documentado, decisión pendiente del desarrollador).
- La duda del scoring I-005 (bonus de incidentes: 75→85 por 3 fases kill chain) queda pendiente y documentada: sin cambio hasta decisión del desarrollador en la fase G.

## Pendientes inmediatos

- Verificación manual de las fases A + B + C + D + E + F + pulido del informe por el desarrollador (pasos abajo).
- Aviso de build: el bundle de Vite supera 500 kB por Recharts; code-splitting queda para la fase G (rendimiento).
- Decisión pendiente del desarrollador: si los 26 páginas (vs objetivo 15–20) se recortan en anexos o se queda así, y si el bonus I-005 (+10 por fases kill chain, 75→85) se ajusta o se mantiene (paso de F sin tocar).
- Al hacer commit (lo hace el desarrollador): sugerencia de mensaje → `fase F + ajustes IA por UI: informe completo, PDF, exportaciones y ajustes de IA en memoria`.

## Cómo ejecutar y probar

- Arrancar todo: `.\start.ps1` (backend http://127.0.0.1:8000 · frontend http://127.0.0.1:5173).
- Tests: `.\test.ps1` → 150 tests verdes (24 fase A + 35 detección/API + 21 correlación/fase C + 10 dashboard/fase D + 25 IA/fase E + 23 informe/fase F pulido + 8 ajustes IA por UI post-F + 6 parser LLM robusto + 2 regresión pool validador; ajustes de cuenta del pulido del informe).
- API docs: http://127.0.0.1:8000/docs (endpoints `/api/detection/rules`, `/api/sessions/{id}/findings`, `/api/sessions/{id}/coverage`, `/api/sessions/{id}/incidents`, `POST /api/sessions/{id}/overrides`, `/api/sessions/{id}/stats`, `/api/ai/settings`, `POST /api/ai/test`, `POST|GET /api/sessions/{id}/narrative`; fase F: `GET /api/sessions/{id}/report`, `PUT /api/sessions/{id}/report/meta`, `PUT /api/sessions/{id}/report/sections/{section_id}`, `POST .../report/sections/{section_id}/regenerate`, `GET /api/sessions/{id}/report/pdf`, `GET /api/sessions/{id}/exports/iocs.csv`, `GET /api/sessions/{id}/exports/findings.json`; `/events` admite `time_from`/`time_to`).

## Recordatorios

- Regla de oro: todo hallazgo debe tener evidencia con `Log_ID`; si no, frase exacta: "No hay evidencia en los logs proporcionados."
- La IA no detecta (implementado en fase E): solo redacta a partir de hallazgos deterministas y su salida se valida; el chat llega en F2.
- Commits/push los hace el desarrollador; agentes solo git de lectura.

## Fase F — qué quedó hecho

### Backend
- **`reporting/report.py`** (informe completo, PLAN §9): construye de forma determinista **14 secciones numeradas + 3 anexos** (58 secciones con el Excel de ejemplo: 1 portada + resumen + metodología + tabla resumen + 37 hallazgos + 6 incidentes + evidencias + timeline/MITRE + criticidad + impacto + plan de acción + IoCs + recomendaciones + limitaciones + anexos de calidad/cobertura/alias). Cada sección lleva `number`, `section_id`, `title`, `kind`, `paragraphs` (Hecho/Inferencia/Hipótesis con citas), `tables` (con columnas y filas de datos reales) y `edited/edited_at`. Los párrafos de resumen/hallazgos/incidentes provienen de la redacción de la fase E (`result.narrative`) si existe, o de las plantillas deterministas. Regla de oro: secciones sin datos usan la frase exacta "No hay evidencia en los logs proporcionados." Tablas derivadas solo de datos: portada (datos del caso), resumen de hallazgos (ID, regla, severidad, score, banda, MITRE, entidades), evidencias (Log_ID + **texto literal de la fila** reconstruido de `raw.fields` con los nombres de columna), timeline de incidentes, técnicas MITRE, criticidad de hallazgos/incidentes con factores y overrides, IoCs por incidente, anexos de calidad (métricas + nulos por columna), cobertura y alias.
- **Edición de secciones**: `parse_section_text()` convierte el texto del analista en párrafos etiquetados (una línea por párrafo; prefijos opcionales `Hecho:`/`Inferencia:`/`Hipótesis:`, sin prefijo = Hecho; `source: manual`). `apply_section_edit()` valida sección conocida (404 si no), no vacía, ≤20.000 caracteres y ≤50 párrafos, y guarda la edición en `AnalysisResult.report_edits` (nuevo campo, en memoria como el resto). `build_report()` aplica las ediciones sobre la base. `regenerate_section()` elimina la edición y devuelve la sección base exacta (plantilla/narrativa).
- **`reporting/pdf.py`**: HTML A4 con Jinja2 (**autoescape activado**; la evidencia siempre es texto escapado, sin HTML crudo) con portada (título + tabla de datos del caso), índice de todas las secciones numeradas, chips de etiqueta Hecho/Inferencia/Hipótesis con colores, citas de evidencia por párrafo y tablas con estilo. El PDF se imprime con **Playwright sync API + Chromium local en caché** (chromium-1234 ya instalado, sin descargas en tiempo de ejecución): `format="A4"`, `display_header_footer` con pie "SOC L2 SIEM Analyzer — Página X de Y" (**numeración de páginas**). Errores de render → HTTP 500 con mensaje claro en español (sin trazas internas).
- **`reporting/exports.py`**: `sanitize_csv_cell()` añade prefijo `'` a celdas que empiezan por `=`, `+`, `-`, `@`, tab o CR (PLAN §11, anti-inyección de fórmulas); `iocs_csv()` agrega los IoCs de todos los incidentes (tipo, valor, incidentes donde aparece, ordenado determinista) y `findings_json()` vuelca los hallazgos del motor con overrides aplicados y sin texto de redacción.
- **`api/routes_report.py`** (nuevo router, tags "report"):
  - `GET /api/sessions/{id}/report` — informe completo con ediciones aplicadas (404 sin sesión/sin análisis).
  - `PUT /api/sessions/{id}/report/sections/{section_id}` — edita una sección (texto → párrafos etiquetados).
  - `POST /api/sessions/{id}/report/sections/{section_id}/regenerate` — restaura el contenido base.
  - `GET /api/sessions/{id}/report/pdf` — genera el PDF en `data/exports/<uuid>.pdf` (git-ignorada) y lo devuelve como descarga con nombre `informe_<archivo>_<hoja>.pdf`; **BackgroundTask borra el temporal justo después de enviarlo** (borrado tras procesar, PLAN §11).
  - `GET /api/sessions/{id}/exports/iocs.csv` y `GET .../exports/findings.json` — descargas con `Content-Disposition` y BOM UTF-8 en el CSV (apertura correcta en Excel).
- **`main.py`**: router registrado; health y versión pasan a fase F.

### Frontend (`frontend/src`)
- **Pestaña nueva "Informe"** (`components/ReportPanel.tsx`), entre Hallazgos y Redacción:
  - Cabecera con nº de secciones, fecha de generación y **tres botones de descarga**: PDF (con estado "Generando PDF…"), IoCs CSV y Hallazgos JSON (descarga vía blob + `Content-Disposition`; el nombre de archivo lo propone el backend).
  - Buscador de secciones por título o id; secciones plegables numeradas con badge de "editada" (fecha/hora) y contador de tablas/filas.
  - Cada párrafo muestra su etiqueta (Hecho/Inferencia/Hipótesis con colores coherentes con la fase E), su origen (`plantilla` / `IA validada` / `manual`) y citas `Log_ID` clickeables que abren la fila cruda en Eventos.
  - Tablas renderizadas de los datos del informe; los `Log_ID` de la tabla de evidencias y de la columna de evidencia del timeline son clickeables.
  - **Editar sección**: textarea con una línea por párrafo (prefijos de etiqueta documentados en la UI); Guardar/Cancelar. **Regenerar** (visible solo en secciones editadas) restaura la plantilla sin recargar la página.
- `api.ts`: `getReport`, `editReportSection`, `regenerateReportSection`, `downloadReportPdf`, `downloadIocsCsv`, `downloadFindingsJson` (helper `downloadBlob` reutilizable). `types.ts`: `ReportResponse`, `ReportSection`, `ReportParagraph`, `ReportTable`. `App.tsx`: pestaña "Informe" añadida a la navegación.

## Validación fase F (18 tests nuevos; suite completa: 130 verdes)

- Estructura: las secciones fijas del PLAN §9 existen, numeración consecutiva 1..N, toda sección con título y ≥1 párrafo; una sección por hallazgo y por incidente; la tabla resumen coincide con el motor (mismo nº de filas, mismos IDs, `evidence` == `len(evidence_log_ids)`).
- Evidencias: la tabla `evidencias` contiene exactamente los `Log_ID` citados por todos los hallazgos, con texto literal `columna=valor`.
- IoCs: cada fila de la sección/tabla procede de los `iocs` de su incidente; sin IoCs → frase obligatoria y sin tablas.
- Sin hallazgos: el informe usa la frase exacta en resumen e impacto (construcción directa de `AnalysisResult` vacío).
- Edición: etiquetas parseadas (Hecho/Inferencia/Hipótesis + sin prefijo = Hecho, `source: manual`); PUT edita, GET refleja `edited=True` y `edited_at`; POST regenerar restaura el texto base exacto; validaciones 400 (vacía, >20.000 chars) y 404 (sección inexistente, en PUT y regenerar).
- PDF: el HTML contiene portada, índice, tablas, `Log_ID` y evidencia literal, sin `<script`; render real con Chromium devuelve `application/pdf`, firma `%PDF-`, >100 kB y **el temporal se borra** tras enviarlo (BackgroundTask verificado en tests); endpoints PDF/informe → 404 sin sesión o sin análisis.
- Exportaciones: `sanitize_csv_cell` neutraliza `=`/`+`/`-`/`@`; el CSV lleva cabecera `tipo,valor,incidentes` y todas sus filas proceden de los IoCs del análisis; el JSON del motor tiene el mismo nº de hallazgos que la API, evidencia idéntica y refleja un override recién creado (sin párrafos de redacción).

## Decisiones tomadas (fase F)

- El informe se construye **siempre determinista** desde los datos estructurados; la única prosa que incorpora es la redacción validada de la fase E (plantillas o IA validada). Las secciones nuevas (metodología, impacto, plan de acción, recomendaciones, limitaciones) salen de agregados factuales o plantillas genéricas por categoría, nunca de señales del ejemplo.
- El "plan de acción" usa acciones genéricas por categoría de regla (autenticación, ejecución, persistencia…) con "Responsable: por asignar / Plazo: por asignar": es una plantilla editable por el analista, no una afirmación del motor.
- La numeración de páginas vive en el pie del PDF (Playwright `pageNumber/totalPages`); el índice lista las secciones numeradas (el número de página exacto de cada sección en el índice HTML es inviable con Chromium sin doble pasada; queda documentado así).
- Las ediciones del analista se guardan en memoria (`AnalysisResult.report_edits`), coherente con la sesión en memoria del PLAN; regenerar elimina la edición y vuelve al contenido base. El texto editado se guarda como párrafos etiquetados, no como HTML.
- El PDF se genera bajo demanda y se borra justo después de la descarga (BackgroundTask): `data/exports/` no acumula informes; la carpeta es git-ignorada.
- El CSV usa `utf-8-sig` (BOM) para que Excel respete el UTF-8, y `sanitize_csv_cell` protege contra inyección de fórmulas antes de escribir cualquier celda.
- Ocurrió durante la fase: `start.ps1` dejó uvicorns huérfanos de una sesión anterior (respondían "fase E" en el 8000 y bloqueaban el nuevo). Si al arrancar el health no muestra `"fase":"F"`, matar los `python.exe` de uvicorn residuales y relanzar.

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

## Validación fase A contra el Excel de ejemplo (715 filas)

- Mapeo automático con confianza 100% en las 12 columnas (sin hardcodear descubrimiento: usa sinónimos genéricos en campo nombres de columnas estandarizados).
- 715 filas normalizadas; timestamps: 715 válidos (hora de pared, sin zona); duplicados de Log_ID: 0.
- Alias detectados: `DC-01 ↔ DC01` como **probable** (inferencia, no fusionados por sí solos); `CORP\backupsvc ↔ CORP\svc_backup` como **candidate** (no se fusionan).
- Distribución `result_norm`: success 598 · failure 108 · error 9 (coherente con códigos HTTP 200/404/500 mapeados a success/failure/error).

## Decisiones tomadas (fase A)

- Fase A no usa pandas: `openpyxl` read-only + `data_only` alcanza para leer sin ejecutar fórmulas; pandas se puede incorporar después si se necesita para el dashboard.
- Los filtros de tabla se formulan con nombres normalizados de campo (`host_raw`, etc.); los nombres exactos de columna cruda pueden variar por archivo.
- Los archivos subidos se guardan en `data/uploads/<uuid>.xlsx` (git-ignorado) durante la vida de la sesión y se borran al eliminar la sesión; no se requiere re-subir al cambiar mapeo o cabecera.
- Sesiones evictadas víctima de tope de sesiones dejan su archivo en `data/uploads/` hasta cerrarse de forma ordenada (limpieza manual de restos previstos en fase G).
- Alias: `created/confirmed/rejected` por analista llega con la correlación (fase C); fase A solo detecta base.
- "Unir todas las hojas" se pospone a la integración multi-hoja (no es crítico: el archivo de ejemplo tiene 1 hoja); fase A analiza hojas de forma independiente.

