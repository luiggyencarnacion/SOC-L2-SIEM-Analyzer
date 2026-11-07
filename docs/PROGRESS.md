# PROGRESS.md — Estado del proyecto

Última actualización: fase E implementada (plantillas deterministas, adaptadores IA y anti-alucinación; fases 0, A, B1, B2, C y D cerradas).

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
| F | pendiente | Informe completo y PDF. |
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

## Pendientes inmediatos

- Verificación manual de las fases A + B + C + D + E por el desarrollador (pasos abajo).
- Aviso de build: el bundle de Vite supera 500 kB por Recharts; code-splitting queda para la fase G (rendimiento).
- Si conviene, limpiar restos de `data/uploads/` de sesiones que murieron con la recarga del servidor (git-ignorado, sin riesgo de commit).
- Al hacer commit (lo hace el desarrollador): sugerencia de mensaje → `fase E: plantillas deterministas, adaptadores IA y validador anti-alucinacion`.

## Cómo ejecutar y probar

- Arrancar todo: `.\start.ps1` (backend http://127.0.0.1:8000 · frontend http://127.0.0.1:5173).
- Tests: `.\test.ps1` → 112 tests verdes (24 fase A + 34 detección/API + 19 correlación/fase C + 10 dashboard/fase D + 25 IA/fase E).
- API docs: http://127.0.0.1:8000/docs (endpoints `/api/detection/rules`, `/api/sessions/{id}/findings`, `/api/sessions/{id}/coverage`, `/api/sessions/{id}/incidents`, `POST /api/sessions/{id}/overrides`, `/api/sessions/{id}/stats`, `/api/ai/settings`, `POST /api/ai/test`, `POST|GET /api/sessions/{id}/narrative`; `/events` admite `time_from`/`time_to`).

## Recordatorios

- Regla de oro: todo hallazgo debe tener evidencia con `Log_ID`; si no, frase exacta: "No hay evidencia en los logs proporcionados."
- La IA no detecta (implementado en fase E): solo redacta a partir de hallazgos deterministas y su salida se valida; el chat llega en F2.
- Commits/push los hace el desarrollador; agentes solo git de lectura.

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

