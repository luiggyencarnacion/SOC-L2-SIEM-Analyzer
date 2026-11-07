# PLAN.md — SOC L2 SIEM Analyzer

> Plan aprobado para el reto final del Bootcamp SOC L2.
> Todas las decisiones aquí recogidas son el punto de verdad para las siguientes fases.
> No se hardcodean IPs, usuarios, hostnames, hallazgos ni señales del Excel de ejemplo.

## 1. Alcance y regla de oro

- Aplicación web local para analizar logs exportados de un SIEM en formato `.xlsx`.
- Uso real de un Analista SOC Nivel 2: carga, normalización, detección por reglas, correlación, incidentes, clasificación de riesgo e informe técnico exportable a PDF.
- Regla de oro de rigor analítico:
  - Cada hallazgo se sustenta estrictamente en filas reales del archivo cargado.
  - Todo hallazgo lista sus `Log_ID` o números de fila, y la UI permite abrir esas filas.
  - Si algo no puede afirmarse con los logs, el informe usa la frase exacta: **“No hay evidencia en los logs proporcionados.”**
  - Se separa siempre: **Hecho**, **Inferencia** e **Hipótesis/pendiente de validar**.
  - La IA **no detecta ni inventa**: solo redacta y resume a partir del resultado del motor determinista.

## 2. Stack final

| Capa | Tecnología | Motivo |
|---|---|---|
| Backend | Python 3.13 + FastAPI + Uvicorn | Simple, local, rápido de arrancar. |
| Lectura Excel | `openpyxl` en modo lectura + `pandas` | No ejecuta macros ni fórmulas. |
| Reglas | YAML + motor determinista en Python | Umbrales y reglas auditables, sin IA en la detección. |
| Frontend | React 19 + Vite 8 + TypeScript 5.9 + Tailwind 4 | Desarrollo rápido y tipado; TS 5.9 por estabilidad. |
| Gráficos | Recharts | Interactividad y tooltips sencillos. |
| PDF | Jinja2 + HTML + Playwright 1.62 con Chromium 1234 en caché | Sin descargar navegador; diseño profesional. |
| IA | Interfaz propia + adaptadores REST con `httpx` | Sin SDKs: Gemini, Anthropic, OpenAI-compatible y Ollama. |
| Estado | Sesión en memoria + archivos temporales ignorados | Sin base de datos obligatoria. |
| Arranque | `.\start.ps1` | Un solo comando local para backend + frontend. |

**Restricciones permanentes:**

- Sin Microsoft Sentinel ni SIEM en vivo.
- Sin instalaciones globales ni cambios de PATH.
- Sin secretos en el repositorio.
- Sin hardcodear IPs, usuarios, hostnames ni hallazgos del ejemplo.
- CORS y bind solo en `127.0.0.1` / `localhost`.

## 3. Estructura de carpetas y arranque

```text
SOC_L2_PROJECT/
├─ backend/
│  ├─ app/
│  │  ├─ api/
│  │  ├─ core/
│  │  ├─ ingestion/
│  │  ├─ detection/rules/default_rules.yaml
│  │  ├─ correlation/
│  │  ├─ reporting/
│  │  ├─ ai/providers/
│  │  ├─ models/
│  │  └─ services/
│  └─ tests/
├─ frontend/
├─ data/
│  ├─ sample/
│  ├─ uploads/       # ignorada
│  ├─ exports/       # ignorada
│  └─ sessions/      # ignorada, opcional
├─ docs/
│  ├─ PLAN.md
│  └─ PROGRESS.md
├─ start.ps1         # único punto de arranque
├─ test.ps1          # ejecución de tests
├─ .env.example
├─ .gitignore
├─ AGENTS.md
├─ README.md
└─ requirements.txt
```

Rutas de arranque: **`.\start.ps1`** y **`.\test.ps1`**, ambas en la raíz. No queda ninguna referencia a `scripts\start.ps1`.

## 4. Modelo de datos, identidades y tipos de afirmación

### 4.1 Entidades principales

- `AnalysisSession`: archivo, hojas, mapeo, eventos, calidad, cobertura, hallazgos, incidentes, informe, estado IA.
- `EventRecord`: `log_id`, `row_number`, `sheet_name`, `timestamp_raw`, `timestamp_parsed`, `timestamp_status`, `host_raw`, `host_key`, `host_alias`, `user_raw`, `user_key`, `user_alias`, `event_code`, `event_description`, `source_ip`, `source_ip_scope`, `destination_raw`, `destination_host`, `destination_ip`, `destination_port`, `log_source`, `process_command_line`, `process_name`, `parent_process`, `result_raw`, `result_norm`, `severity_siem`, `logon_type`, `http_method`, `http_status`, `url_path`, `share`, `file_path`, `bytes_out`, `task_name`, `service_name`, `extracted`, `raw`, `quality_flags`.
- `IdentityAlias`: relación entre valores crudos y canónicos, con `status`, `rationale`, intervención del analista.
- `RuleDefinition`: `id`, `name`, `category`, `description`, `rationale`, `base_severity`, `required_fields`, `optional_fields`, `parameters`, `mitre`, `enabled`, `use_probable_aliases`.
- `Finding`: hallazgo con secciones, factores, evidencia, MITRE, `statements` Hecho/Inferencia/Hipótesis, override manual.
- `Incident`: grouping de hallazgos, timeline, fases kill chain, MITRE, IoCs, clasificación y justificación.
- `IoC`: IP, dominio/URL, archivo, servicio, tarea, cuenta, hash si existe.
- `AnalysisCoverage`: estado de cada regla y por qué se omitió.
- `DataQualityReport`: nulos, duplicados, tipos mezclados, alias, discrepancies de severidad, campos riesgosos.
- `RiskScore`, `ManualOverride`, `ReportSection`, `AIState`.

### 4.2 Política de identidades y alias

- El valor original (`host_raw`, `user_raw`) **nunca se sobrescribe**. La normalización crea una clave aparte (`host_key`, `user_key`).
- Estados de alias:
  - `exact`: misma identidad tras limpiar espacios/mayúsculas.
  - `probable`: misma clave normalizada, pero los valores originales difieren; se etiqueta como **inferencia**.
  - `candidate`: valores parecidos pero con claves distintas; **no se fusionan**.
- `DC-01` / `DC01`: clave canónica `dc01`, estado `probable`; en UI e informe se muestra “DC-01 / DC01 — probable mismo host (inferencia)”. Las tablas de evidencia muestran el valor literal de cada fila.
- `backupsvc` / `svc_backup`: claves distintas; relación `candidate` “posible cuenta similar (inferencia)”; no se agrupan automáticamente. El analista puede confirmar o rechazar.
- Toda relación por alias es reversible y aparece en el anexo de calidad de datos.
- La correlación solo usa identidades `exact` o confirmadas para agrupar con fuerza. Las `probable`/`candidate` generan una **relación posible**, no una fusión definitiva.
- Cada afirmación se etiqueta como **Hecho**, **Inferencia** o **Hipótesis/pendiente**.

### 4.3 Normalización clave

- `Event_ID` siempre texto.
- `Result` mapeado a `success/failure/denied/error/other` conservando el original; códigos HTTP a `http_status`.
- Timestamps: sin conversión de zona horaria; se respeta el offset si existe; si es naive, se trata como hora de pared y se declara desconocida.
- IPs validadas con `ipaddress`; clasificación privada/pública/loopback/inválida.
- Extracción desde texto libre con regex para IPs, usuarios, rutas, URLs y comandos; se marca como `extraído del texto`.
- `raw` conserva toda la fila original para la evidencia.

## 5. Ingesta, normalización y tabla

- Solo `.xlsx`; se rechazan `.xls`, `.xlsm`, archivos corruptos, cifrados o sin hojas.
- Límites configurables: 25 MB, 50 hojas, 100 columnas y 100.000 filas.
- Comprobación de extensión + firma ZIP + estructura interna; nunca se ejecutan macros ni fórmulas.
- Se rechaza si no hay ni timestamp ni al menos una identidad (usuario, IP o host).
- Selector de hojas con dimensiones y vista previa.
- “Unir todas” solo si comparten el mismo esquema normalizado; si difieren, mapeo por hoja y aviso.
- Detección automática de cabecera y alias para los campos universales.
- Puntuación de confianza del mapeo y pantalla de mapeo manual si algo falta.
- Tabla de eventos con paginación 50/100/250, búsqueda global, filtros por columna, ordenamiento, panel de fila cruda y filtro global reutilizable.
- Objetivo de rendimiento: 10.000–50.000 filas sin congelar la UI.

## 6. Motor de detección

### 6.1 Configuración YAML

Cada regla declara: `id`, `name`, `category`, `description`, `rationale`, `base_severity`, `enabled`, `required_fields`, `optional_fields`, `parameters`, `mitre`, `evidence_limit`, `use_probable_aliases`.

Campos abreviados: `ts`, `host`, `user`, `src_ip`, `dst`, `event_code`, `msg`, `cmd`, `result`, `logon_type`, `http`, `share`, `file_path`, `bytes_out`, `task_service`, `sev_siem`.

### 6.2 Reglas aprobadas

**Autenticación**
- `AUTH-001` Fuerza bruta por usuario/IP — `ts`, `user` o `src_ip`, `result`/`event_code` — Alto — T1110.001.
- `AUTH-002` Password spraying — `ts`, `src_ip`, `user`, `result` — Alto — T1110.003.
- `AUTH-003` Éxito después de fallos — `ts`, `user` o `src_ip`, `result`/`event_code` — Alto — T1078.
- `AUTH-004` Login desde IP pública hacia activo interno — `ts`, `src_ip`, `host`, `result` — Alto — T1078/T1133.
- `AUTH-005` RDP/LogonType 10 sospechoso — `ts`, `logon_type`, `src_ip` o `user`, `result` — Alto — T1021.001.
- `AUTH-006` Cuenta desde origen/host nunca visto — fase opcional H.
- `AUTH-007` Cuenta de servicio/helpdesk interactiva u origen raro — Alto — T1078.002.
- `AUTH-008` Actividad fuera de horario — factor contextual en H.

**Privilegios**
- `PRIV-001` Altas/cambios en cuentas o grupos privilegiados — Alto.
- `PRIV-002` Asignación de privilegios especiales 4672 en contexto anómalo — Medio.

**Ejecución y evasión**
- `EXEC-001` PowerShell encoded/bypass/hidden — Alto.
- `EXEC-002` Reconocimiento `whoami`/`net`/`ipconfig`/`systeminfo` — Medio.
- `EXEC-003` LOLBins/dual-use — Alto.
- `EXEC-004` Borrado de sombras — **Crítico**.
- `EXEC-005` Compresión/staging sobre rutas sensibles — Alto.
- `EXEC-006` Binario en ruta no estándar — Medio.
- `EXEC-007` Parent-child anómalo o 4104 — Medio/Alto.

**Persistencia**
- `PERS-001` Tarea programada creada (4698) — Medio.
- `PERS-002` Servicio instalado (7045/4697) — Alto.
- `PERS-003` Ejecución periódica/beaconing — Medio.

**Movimiento lateral**
- `LAT-001` Movimiento lateral anclado a acceso externo/RDP — Alto — T1021/T1078.
- `LAT-002` Acceso a shares SMB sensibles — Medio.
- `LAT-003` Cadena de LogonType 3 multi-salto — Medio.
- `LAT-004` Host interno con actividad externa nueva — Medio.

**Exfiltración**
- `EXF-001` Conexión saliente externa desde servidor/proceso inusual (5156) — Alto.
- `EXF-002` POST salientes repetidos o `bytes_out` grande — Alto.
- `EXF-003` Subidas periódicas al mismo destino — Alto.
- `EXF-004` Lectura masiva en carpetas sensibles (4663) — Alto.

**Web**
- `WEB-001` Ráfaga de 404/500 — Medio.
- `WEB-002` Enumeración de admin/login con usuario en URL — Medio.
- `WEB-003` Webshell/inyección de comandos en URL o proceso hijo de IIS con shell — **Crítico**.

**Línea base**
- `BASE-001` Volumen atípico por host/usuario/IP — fase opcional H.
- `BASE-002` IP externa en eventos de sistema no web — fase opcional H.

### 6.3 Precisiones clave

- **AUTH-001 / AUTH-002:** los fallos de fuerza bruta de las víctimas de un spraying se absorben en el hallazgo `AUTH-002`; solo se conserva un hallazgo superior y el detalle por usuario dentro de `absorbed_detail`. El evento de éxito de `AUTH-003` no se absorbe.
- **AUTH-007:** solo aplica a patrones configurables (`svc_*`, `helpdesk`, etc.), con logon interactivo o shell y una condición adicional (IP pública, host fuera de baseline, 4672 cercano o persistencia cercana). La actividad normal de helpdesk no genera hallazgo solo.
- **LAT-001:** exige un ancla en los 30 min previos (login externo exitoso, RDP público, o éxito tras fallos) y después un LogonType 3, share o `source=<host>` en un host distinto dentro de 30 min. No inflan usuarios internos normales.
- **LAT-003:** solo se evalúa con ancla de `LAT-001`; con un salto se absorbe en LAT-001; con ≥2 saltos genera hallazgo.
- **LAT-002:** solo shares sensibles o tras ancla sospechosa.
- **LAT-004:** exige baseline interno mínimo y destino externo no visto antes.
- **Criterio de precisión B1/B2:** ninguna cuenta o IP benigna aislada genera hallazgo; total de hallazgos con la config por defecto: **25–50, nunca cientos**.
- **Cobertura:** cada regla reporta `executed`, `skipped_missing_fields`, `skipped_disabled`, `insufficient_data` o `error`, con motivo.

### 6.4 Correlación e incidentes

- Grafo de entidades: cuenta, host, IP origen, destino externo, share, ruta, tarea/servicio y proceso.
- Ventana temporal por defecto: **90 minutos**, configurable.
- **Nunca se agrupa solo por compartir host.** Si dos cadenas usan el mismo servidor con cuentas y horarios distintos, se mantienen como incidentes independientes y se cruzan como “mismo activo”.
- Análisis explícto de relación: entidades compartidas, distancia temporal y conclusión “relacionado / independiente / relación posible por alias (inferencia)”.
- Cada incidente entraña: timeline, activos/cuentas afectadas, IoCs, fases kill chain, MITRE, vector de entrada probable solo con evidencia y justificación de agrupación.
- Cada fase se marca solo si está observada; no se inventan fases “probables”.
- El ejemplo con la config por defecto debe producir **6 cadenas**.

## 7. Scoring

### 7.1 Bases y bandas coherentes

| Severidad base | Score base | Banda sin factores |
|---|---:|---|
| Bajo | 20 | Bajo (0–39) |
| Medio | 45 | Medio (40–59) |
| Alto | 65 | Alto (60–79) |
| Crítico | 85 | Crítico (80–100) |

**Invariante:** una regla con `base_severity = X` y sin factores adicionales cae exactamente en la banda X.

`EXEC-004` y `WEB-003` son `base_severity: Crítico`.

### 7.2 Factores adicionales

| Factor | Puntos |
|---|---:|
| Origen público/externo | +5 |
| Cuenta o contexto privilegiado | +10 |
| Activo crítico configurable | +10 |
| Acceso a datos sensibles | +5 |
| Volumen >50 MB | +10 |
| Multi-host (≥3 hosts) | +5 |
| Persistencia | +5 |
| Evasión (encoded PS, borrado de sombras) | +5 |
| Repetición/periodicidad | +5 |
| Explotación web | +5 |
| **Tope total de factores** | **+30** |

- `score_hallazgo = min(100, base + factores)`.
- El “éxito tras fallos” ya está codificado en la base de `AUTH-003`; no se suma dos veces.
- `score_incidente = min(100, max(score_hallazgos) + 5 × (fases_observadas − 1))`, bonus máximo +15.
- La severidad del SIEM no influye en el puntaje.
- El override manual conserva el score automático y añade la clasificación manual con motivo obligatorio.
- `vssadmin` (`EXEC-004`) es Crítico desde su base, sin depender de factores.

## 8. Dashboard

- KPIs: eventos totales, hallazgos por criticidad, incidentes, activos y cuentas afectadas, rango temporal, reglas ejecutadas/omitidas y alertas de calidad.
- Gráficos: hallazgos por criticidad, timeline de eventos con picos, top IPs/usuarios/hosts, distribución por `Event_ID`/`Log_Source`, heatmap hora × día u hora × host, severidad SIEM vs calculada, tácticas MITRE.
- Interacción: clic en gráfico aplica filtro global; chips y reset; drill-down a tabla filtrada; row click abre evidencia cruda.
- Tema claro/oscuro, colores accesibles y etiquetas además de color.

## 9. Informe técnico y PDF

1. Portada y datos del caso.
2. Resumen ejecutivo.
3. Metodología, alcance, cobertura y limitaciones.
4. Tabla resumen de hallazgos.
5. Explicación técnica por hallazgo.
6. Evidencias con `Log_ID` y texto literal.
7. Timeline e MITRE.
8. Criticidad y justificación por hallazgo e incidente.
9. Impacto observado.
10. Plan de acción: investigar, contener y remediar, con responsable y plazo.
11. IoCs.
12. Recomendaciones generales.
13. Limitaciones.

Anexo: calidad de datos, cobertura, alias inferidos y discrepancias de severidad.

- Cada sección editable; regeneración de sección individual.
- Las tablas de evidencia se generan desde los datos; sin texto inventado.
- Si no hay evidencia, se usa la frase exacta obligatoria.
- PDF A4 con portada, índice, encabezados, tablas y numeración de páginas.
- Exportaciones extra: IoCs a CSV (protección contra inyección de fórmulas) y hallazgos a JSON.

## 10. IA

- `AI_PROVIDER=none | gemini | anthropic | openai_compatible | ollama`; por defecto `none`.
- Sin modelo fijo en código; `AI_MODEL` obligatorio para activar IA.
- Claves solo en `.env` del backend; la UI las recibe/muestra nunca.
- Pantalla de ajustes: proveedor, modelo, base URL, estado de clave y prueba de conexión.
- Anti-alucinación independiente del proveedor:
  - Solo se envían hallazgos estructurados y filas de evidencia.
  - El LLM debe citar `Log_IDs`.
  - Backend valida existencia, pertenencia, cifras, IPs, usuarios, hosts y horas.
  - Si falla, se descarta el párrafo y se usa la plantilla; se registra el motivo.
  - Temperatura baja y respuesta JSON con párrafos + citas.
- Enmascaramiento reversible para proveedores cloud; Ollama local sin enmascaramiento por defecto.
- Chat IA se implemente después de la fase F (Fase F2).
- Tests de adaptadores con `httpx.MockTransport`, sin llamadas reales.

## 11. Seguridad de la aplicación

- Validación de tamaño, extensión, firma ZIP y estructura; sin macros ni evaluación de fórmulas.
- React escapa por defecto; Jinja2 autoescape; nada de `innerHTML`; evidencia siempre como texto.
- CSV: prefijo `'` en celdas que empiecen por `=`, `+`, `-` o `@`.
- CORS y bind solo `127.0.0.1` / `localhost`.
- `.env` ignorado; `.env.example` sin secretos; log con redacción de claves y sin prompts completos por defecto.
- Sesiones UUID; nombres de archivo temporales; borrado tras procesar; sin path traversal.
- Límites de filas/hojas/tamaño y una sola análisis concurrente.
- Mensajes de error claros en español, sin trazas internas en la UI.

## 12. Fases y criterios de terminado

Orden: **0 → A → B1 → B2 → C → D → E → F → F2 → G → H (opcional)**.

- **Fase 0 (docs):** docs base, `.gitignore`, `AGENTS.md`, `PROGRESS.md`, esqueleto de `start.ps1`/`test.ps1`. Criterio: la app arranca con placeholder/health y `git status` muestra uploads ignorados.
- **Fase A:** ingesta, hojas, mapeo, normalización, calidad y tabla. Criterio: subir el Excel, ver 715 filas, buscar/filtrar/ordenar, cambiar hoja/mapeo, ver alias y nulos; archivo inválido rechazado; tests verdes.
- **Fase B1:** reglas AUTH-001–005, AUTH-007, PRIV-001/002, EXEC-001–007, PERS-001–003. Criterio: spraying, RDP admin, encoded PS, vssadmin, persistencia y privilegios detectados sin duplicados AUTH-001, sin hallazgos benignos aislados, total 25–50, cobertura y tests verdes.
- **Fase B2:** reglas LAT-001–004, EXF-001–004, WEB-001–003. Criterio: LAT-001 anclado a la cadena admin, LAT-003 solo con ≥2 saltos, lectura masiva/exfiltración/webshell detectados, sin ruido interno, total 25–50 y sin hallazgos benignos aislados.
- **Fase C:** correlación, incidentes, scoring y override. Criterio: 6 cadenas, timeline, IoCs, MITRE, clasificación coherente, override manual registrado.
- **Fase D:** dashboard interactivo. Criterio: gráficos que filtran, drill-down, heatmap, comparación SIEM vs calculada y navegación.
- **Fase E:** plantillas deterministas, adaptadores IA y anti-alucinación. Criterio: `AI_PROVIDER=none` genera todo por plantillas, ajustes prueba conexión sin exponer claves, validación descarta citas inválidas y usa plantillas.
- **Fase F:** informe completo, PDF y exportaciones. Criterio: editar/regenerar sección, PDF con portada/índice/número de páginas/tablas/evidencia y descargas CSV/JSON.
- **F2 (chat), post-F:** chat de IA sobre el caso. Criterio: respuesta solo con evidencia, citas `Log_IDs`, frase obligatoria si no hay, mismo validador, claves ocultas.
- **Fase G:** pulido, README, errores, rendimiento y seguridad. Criterio: `.\start.ps1`, tema claro/oscuro, estados de carga/error, 10k filas fluidas, checklist completo, suite verde.
- **H (opcional):** `AUTH-006`, `AUTH-008`, `BASE-001`, `BASE-002` tras G. Criterio: reglas om itidas si no hay baseline suficiente y sin inundar hallazgos.

## 13. Tests

- Normalización de columnas, alias, timestamps, IPs, resultados y extracción desde texto.
- Aliases reversibles: `DC-01/DC01` inferencia; `backupsvc/svc_backup` candidato no fusionado.
- Cada regla con caso positivo y negativo en datos sintéticos.
- Correlación: 6 incidentes del ejemplo, independencia y no fusión por host.
- Scoring: bases, factores, tope +30, override y 6 cadenas.
- Adaptadores IA con `httpx.MockTransport`; validador de citas, cifras y entidades.
- Seguridad: tamaño/extension, HTML/JS, CSV injection, CORS, claves no expuestas.
- Integración con el Excel: 715 filas, señales esperadas, ningún hallazgo sin evidencia, controles benignos no marcados.

## 14. Validación contra el Excel

| Cadena | Evidencia principal |
|---|---|
| 1. Spraying DC-01 | 33 fallos desde `203.0.113.74`; éxito `mgarcia` `EVT-00123`; `4672` `EVT-00126`; absorción en `AUTH-002`. |
| 2. RDP admin + lateral | 4 fallos, `EVT-00188`, `EVT-00193`, `EVT-00198`, `EVT-00207`, `EVT-00214`, `EVT-00222/225/227/231`, `EVT-00232`, `EVT-00235`, `EVT-00237`. |
| 3. Backup/Finance + vssadmin | `EVT-00280`, 16 lecturas `EVT-00284`–`EVT-00309`, `EVT-00314`. |
| 4. Legal + exfiltración | `EVT-00419`, `EVT-00428`, 22 POSTs, 253.305.558 bytes. |
| 5. Persistencia helpdesk | `EVT-00523`, `EVT-00524`, cinco ejecuciones periódicas. |
| 6. Ataque web | 21 peticiones HTTP, 404/500, `EVT-00599`. |

Señales que no existe en el ejemplo: `net user`/`net group`, `certutil`, `bitsadmin`, `mshta`, `rundll32`, `reg add`, 4720/4728/4732/4756/4697, hashes y dominios DNS. `whoami` está en la cadena web, no en la RDP de `admin`; `net view` existe como `net.exe view `\\FS-SRV01``.
