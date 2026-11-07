# ROL Y OBJETIVO

Actúa como ingeniero full-stack senior con criterio de seguridad defensiva. Vas a construir desde cero una aplicación web que será mi herramienta de trabajo como Analista SOC Nivel 2. Es el reto final de un Bootcamp de Analista SOC L2. Soy principiante en vibecoding: explícame en español y en lenguaje claro qué vas a hacer antes de hacerlo, y qué comando ejecutar cuando me toque a mí.

Escenario: trabajo en una consultora de ciberseguridad en Estocolmo, Suecia. Un cliente reporta un posible incidente y entrega un Excel (.xlsx) con logs exportados de su SIEM. La app debe permitirme cargar ese Excel, analizarlo, correlacionar eventos, determinar si hubo uno o varios incidentes, clasificar el riesgo y generar un informe técnico profesional exportable a PDF.

Entorno y rutas:
- Sistema: Windows (PowerShell). Usa comandos y rutas válidos en Windows, sin comandos bash.
- Carpeta del proyecto (todo el trabajo ocurre aquí): `C:\Users\Luiggy\SOC_L2_PROJECT`
- Excel de ejemplo: `C:\Users\Luiggy\SOC_L2_PROJECT\data\sample\SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx`. Si no lo encuentras ahí, pregúntame la ruta.
- La app debe funcionar con cualquier otro Excel de logs de SIEM, no solo con ese. Prohibido hardcodear IPs, usuarios, hostnames o hallazgos del ejemplo.

# REGLA DE ORO: RIGOR ANALÍTICO

No se inventan hallazgos. Cada conclusión, hallazgo, afirmación del informe y texto generado por IA debe estar sustentado estrictamente en filas reales del archivo cargado.
- Todo hallazgo debe listar los `Log_ID` (o número de fila) que lo respaldan, y la UI debe permitir abrir esas filas.
- Si algo no puede afirmarse con los logs, el informe dice "no hay evidencia en los logs proporcionados". No se rellena con suposiciones.
- Separa siempre: Hecho (visto en logs), Inferencia (deducción razonada, marcada como tal) e Hipótesis/pendiente de validar.
- El motor de detección es determinista (reglas en código). La IA NO detecta ni inventa: solo explica, resume y redacta a partir de los hallazgos estructurados que le pasa el motor.

# FUNCIONALIDADES REQUERIDAS (las 6 del reto)

1. **Carga de archivos**: subir .xlsx (drag & drop), soportar varias hojas (elegir hoja o unirlas), mostrar vista previa y tabla completa con paginación/virtualización, búsqueda, filtros por columna y ordenamiento. Validar el archivo y mostrar errores claros.
2. **Análisis de seguridad**: motor de reglas que identifica eventos sospechosos y los correlaciona (detalle abajo).
3. **Dashboard**: estadísticas y gráficos interactivos por criticidad (clic en un gráfico filtra el resto).
4. **Clasificación de riesgos**: Crítico, Alto, Medio o Bajo, siempre con justificación.
5. **Informe técnico**: documento estructurado y completo.
6. **Exportación**: descarga del informe en PDF.

# REQUISITOS ADICIONALES

- **Interfaz** moderna, intuitiva y fácil de usar. Tema oscuro tipo SOC con opción de tema claro, tipografía cuidada, jerarquía visual clara, colores de severidad consistentes (Crítico/Alto/Medio/Bajo) y accesibles. Todo el texto de la UI y del informe en español.
- **IA integrada**: apoya el análisis de datos y la redacción del informe (detalle abajo).
- **Sin Microsoft Sentinel**: no se requiere ninguna integración con Sentinel ni con SIEM en vivo. La entrada es solo el Excel.

# STACK SUGERIDO (puedes proponer otro si lo justificas en una línea; prioriza lo simple, soy principiante)

- Backend: Python 3.11+ con FastAPI, pandas y openpyxl. El análisis se hace en el backend.
- Frontend: React + Vite + TypeScript + Tailwind, gráficos con Recharts o ECharts.
- PDF: renderizar el informe en HTML y convertirlo con Playwright/Chromium headless (o WeasyPrint solo si funciona bien en Windows). Debe verse profesional: portada, índice, encabezados, tablas de evidencia, numeración de páginas.
- Local-first: que arranque con un solo comando (documéntalo en el README). Sin base de datos obligatoria; el estado de la sesión puede vivir en memoria o en archivos locales.

# PREFLIGHT Y DEPENDENCIAS (hazlo antes de planear)

- **Chequeo previo, solo lectura:** antes de proponer el plan, detecta qué hay instalado (Python y versión, pip, Node y versión, npm, Git) y qué podría faltar para el stack propuesto (por ejemplo, el navegador Chromium para generar PDF). No instales nada en este paso. Muéstrame una tabla: herramienta, versión encontrada, ¿cumple?, qué falta.
- **Aprobación en bloque:** si falta algo o necesitas paquetes, presenta UNA lista con cada dependencia, para qué sirve y cómo se instalará, y espera mi OK antes de ejecutar. Con ese OK instala todo junto.
- **Solo instalaciones locales al proyecto:** entorno virtual de Python (`.venv`) y `node_modules`. Prohibido instalar globalmente o cambiar configuración del sistema (winget, choco, PATH, políticas de PowerShell, etc.) sin preguntarme aparte y explicarme por qué.
- **Verifica los nombres exactos de los paquetes** antes de instalar (evita typosquatting). Usa solo paquetes conocidos y con versiones fijadas en `requirements.txt` y `package.json`.
- **Durante el desarrollo:** si necesitas una dependencia nueva que no estaba en la lista aprobada, detente y pídemela con motivo, alternativa sin dependencia y tamaño aproximado. No la instales por tu cuenta.
- Nunca descargues ni ejecutes scripts de internet, ni uses `curl | sh` o equivalentes.
- Los comandos que borran, sobrescriben o salen de la carpeta del proyecto requieren mi confirmación.

# GIT Y GITHUB

- La carpeta ya es un repositorio Git (`git init` hecho). El repositorio remoto privado es `https://github.com/luiggyencarnacion/SOC-L2-SIEM-Analyzer`.
- **Los commits y el push los hago yo.** Tú solo puedes ejecutar comandos Git de lectura (`git status`, `git diff`, `git log`, `git ls-files`). Tienes prohibido ejecutar `git commit`, `git push`, `git remote`, `git reset --hard`, `git clean`, `git rebase`, `git checkout` sobre archivos, o cualquier comando con `--force`, y no puedes cambiar el remoto. Al cerrar cada fase, sugiéreme el mensaje de commit con el formato `fase X: descripción corta`.
- **Antes de mi primer commit**, verifica con `git status` y `git ls-files` que `.gitignore` excluye `.env`, `.venv`, `node_modules`, `__pycache__`, carpetas de compilación (`dist`, `build`), PDFs/informes generados con datos y cualquier archivo de logs que yo suba en pruebas (usa una carpeta ignorada como `data/uploads/`). Solo el Excel de ejemplo, que es sintético, puede quedar versionado.
- Si en algún momento una clave, token o dato sensible termina dentro de un archivo que no está ignorado, avísame de inmediato antes de cualquier commit.
- Escribe estas reglas de Git en `AGENTS.md`.

# INGESTA Y NORMALIZACIÓN (clave para que funcione con otros Excel)

- Detección automática de columnas por alias (por ejemplo Timestamp/Time/EventTime/_time, Hostname/Computer/Host, User/Account/Username, Source_IP/SrcIP/ClientIP, Event_ID/EventCode, etc.), más una pantalla de mapeo manual de columnas si falta alguna.
- **Reglas por capacidades:** cada regla declara qué campos necesita (por ejemplo, fuerza bruta requiere timestamp + IP origen o usuario + resultado/evento de fallo). Si el Excel no tiene esos campos, la regla se omite y NO se inventa nada. Tras el análisis, la UI y el informe deben mostrar una tabla "Cobertura del análisis": qué reglas se ejecutaron, cuáles se omitieron y por qué (campo faltante), y qué tipos de ataque quedan sin poder evaluarse con este archivo. Si el archivo no tiene ni timestamp ni al menos un campo de identidad (usuario, IP, host), la app debe rechazarlo con un mensaje claro de qué falta. Además de los alias, si hay una columna de texto libre (mensaje/descripción), extrae IPs, usuarios y comandos con regex como respaldo, marcando esos datos como "extraídos del texto".
- El Excel de ejemplo trae columnas: Log_ID, Timestamp, Hostname, Event_ID, User, Source_IP, Destination, Log_Source, Event_Description, Process_CommandLine, Result, Severity (715 filas, una sola hoja "SIEM Export").
- Maneja los problemas de calidad de datos que ya existen en ese ejemplo:
  - `Event_ID` mezcla números (4624, 4625…) con textos (HTTP_ACCESS, PROXY_ACCESS): tratarlo como string.
  - `Result` mezcla Success/Failure/Allowed con códigos HTTP (200, 404, 500).
  - `Process_CommandLine` a veces no contiene un comando: puede traer URIs, `bytes_out=...`, `TaskName=...`, `ServiceName=...`, rutas de archivo.
  - Hostnames inconsistentes (por ejemplo DC-01 vs DC01) y cuentas de servicio con nombres parecidos: normalizar para correlacionar y reportar la inconsistencia como observación.
  - Usuarios vacíos o "-", Destination nulo, timestamps como texto.
  - La columna `Severity` del SIEM NO es confiable (por ejemplo, fallos de inicio de sesión marcados Informational). Úsala solo como dato de contraste y no como fuente de la clasificación final. Reporta las discrepancias entre la severidad del SIEM y la calculada por la app.
- Conserva el valor original de cada fila para mostrar evidencia literal.
- Soporta archivos de varios miles de filas sin congelar la UI.

# MOTOR DE DETECCIÓN (reglas configurables)

Reglas en un archivo de configuración (YAML/JSON) con umbrales editables (ventana de tiempo, N intentos, horario laboral, redes internas, listas de LOLBins, etc.) y editables desde la UI. Cada regla tiene id, nombre, categoría, severidad base, campos requeridos, mapeo MITRE ATT&CK y explicación. Cubrir como mínimo:

- **Fuerza bruta**: ráfagas de fallos (4625 u homólogos) por IP origen y por usuario en una ventana; password spraying (una IP contra muchos usuarios); **inicio exitoso posterior a fallos** (señal de cuenta comprometida).
- **Inicios de sesión sospechosos**: IP origen externa/no RFC1918 hacia sistemas internos, fuera de horario, RDP (LogonType 10), cuenta que aparece desde IP/host nunca visto, cuentas de servicio o de helpdesk usadas de forma interactiva o desde orígenes raros.
- **Escalamiento de privilegios**: 4672, altas/cambios en grupos privilegiados (4720, 4728, 4732, 4756, etc.), uso de `admin` tras un acceso inusual.
- **Comandos y procesos sospechosos**: PowerShell con `-EncodedCommand`/bypass/hidden, `vssadmin delete shadows`, `whoami`, `net view/user/group`, `certutil`, `bitsadmin`, `mshta`, `rundll32`, `reg add`, compresión/staging (`7z`, `tar`, `rar`, `zip`), binarios en rutas no estándar (`ProgramData`, `Temp`, `Users\Public`), parent-child anómalo (cmd/powershell como padre), script blocks (4104).
- **Persistencia**: tareas programadas (4698), servicios instalados (7045/4697), ejecución repetida y periódica de un mismo binario (posible beaconing, calcula el intervalo).
- **Movimiento lateral**: misma cuenta o IP saltando entre varios hosts en poco tiempo, accesos a recursos compartidos (5140/5145), logon de red (LogonType 3) encadenados, host interno que pasa a ser origen de actividad nueva.
- **Exfiltración y comunicación externa**: conexiones salientes de servidores/procesos inusuales (5156 hacia IP externa), POST salientes repetidos con `bytes_out` grande o volumen acumulado, subidas periódicas hacia un mismo destino, lectura masiva de archivos de carpetas sensibles (4663 sobre rutas tipo Finance/Legal).
- **Ataques web**: ráfagas de 404/500, rutas de administración o login con usuario por URL, webshells (`.aspx?cmd=`), parámetros de ejecución de comandos, exportaciones de API anómalas.
- **Otras anomalías**: cualquier comportamiento fuera de la línea base calculada del propio archivo (hosts/usuarios/IPs con volumen atípico, eventos en horarios raros, IPs externas que aparecen en eventos de sistema).

# CORRELACIÓN E INCIDENTES

- Agrupa hallazgos relacionados en **incidentes** usando entidades compartidas (IP, usuario, host) y cercanía temporal. El objetivo es responder explícitamente: ¿hubo un solo incidente o varios? ¿Están relacionados entre sí o son independientes? Justifica cada agrupación con la evidencia.
- Por cada incidente: línea de tiempo cronológica, activos y cuentas afectadas, IoCs extraídos (IPs, dominios/URLs, hashes si existen, rutas de archivo, nombres de servicio/tarea, cuentas), fases tipo kill chain / tácticas MITRE ATT&CK observadas y vector de entrada probable (solo si hay evidencia).
- Distingue actividad normal de ruido: la mayoría de los logs son benignos, y la app no debe marcar todo como sospechoso. Mantén la precisión por encima de la cantidad de alertas.

# CLASIFICACIÓN DE RIESGO

- Puntaje transparente y explicable (por ejemplo, severidad base de la regla + factores como éxito tras fallos, cuenta privilegiada, activo crítico como DC/File Server/DB, origen externo, volumen de datos, número de fases en la cadena de ataque).
- Resultado: Crítico / Alto / Medio / Bajo, con una justificación en texto ("por qué este nivel") que cite los factores y las filas. Permitir que yo cambie manualmente la clasificación de un hallazgo y anotar el motivo (queda registrado en el informe).
- Cada incidente tiene su clasificación global y cada hallazgo la suya.

# DASHBOARD

- KPIs: total de eventos, hallazgos por criticidad, incidentes detectados, activos y cuentas afectadas, rango temporal.
- Gráficos interactivos: hallazgos por criticidad (donut/barras), línea de tiempo de eventos con picos marcados, top IPs origen, top usuarios, top hosts, distribución por Event_ID/Log_Source, mapa de calor hora × día o hora × host, comparación severidad SIEM vs severidad calculada.
- Interacción: clic en un gráfico filtra tabla y hallazgos, drill-down hasta los logs crudos, filtros globales por rango de tiempo, host, usuario, IP y severidad.
- Vista de detalle de incidente (timeline vertical con fases) y vista de detalle de hallazgo (qué, por qué importa, evidencia, filas).

# IA INTEGRADA

- Capa de IA agnóstica al proveedor (interfaz única con adaptadores: Gemini, Anthropic, OpenAI-compatible y Ollama/local). Configurable por variables de entorno en `.env` (nunca en el código ni en el repo; `.gitignore` debe incluir `.env` desde el primer commit).
- Usos de la IA: (1) resumen ejecutivo, (2) explicación técnica de cada hallazgo en lenguaje claro, (3) redacción de impacto y plan de acción, (4) un chat para preguntar sobre el caso ("¿qué hizo la cuenta X?", "¿por qué este hallazgo es crítico?").
- Anti-alucinación (obligatorio): el prompt al LLM contiene solo los hallazgos estructurados y las filas de evidencia relevantes; el LLM debe citar `Log_ID`; el backend valida que todo `Log_ID` citado exista y que las cifras (conteos, IPs, horas) coincidan con los datos; si falla la validación, se descarta o marca el párrafo y se usa la plantilla determinista. Temperatura baja. Instrucción explícita de "no inferir nada que no esté en la evidencia".
- Privacidad: mostrar un aviso claro de que los logs van a un servicio externo cuando se usa un proveedor en la nube, con opción de enmascarar (IPs/usuarios/hosts con alias reversibles) antes de enviar y la opción de usar un modelo local.

# INFORME TÉCNICO (en español, editable antes de exportar)

Estructura obligatoria:
1. Portada (título, cliente, fecha, analista, clasificación del documento) y datos del caso (archivo analizado, rango temporal, nº de eventos).
2. Resumen ejecutivo (no técnico: qué pasó, gravedad, qué hacer ya).
3. Metodología y alcance (cómo se analizó, reglas aplicadas, cobertura del análisis, limitaciones).
4. Hallazgos identificados (tabla resumen con id, título, criticidad, activos).
5. Explicación técnica de cada hallazgo.
6. Evidencias encontradas en los logs (tablas con Log_ID, timestamp, host, usuario, IP, comando, resultado; textual, sin alterar).
7. Línea de tiempo del/los incidente(s) y mapeo MITRE ATT&CK.
8. Criticidad y justificación (por hallazgo e incidente).
9. Posible impacto en la organización (confidencialidad, integridad, disponibilidad, negocio, cumplimiento), solo con base en lo observado.
10. Plan de acción: Investigar, Contener y Remediar (acciones concretas y priorizadas, con responsable sugerido y plazo, por incidente).
11. IoCs (lista exportable).
12. Recomendaciones generales de seguridad.
13. Limitaciones y qué no se pudo determinar con los logs.
Anexo: observaciones de calidad de datos.
Permitir editar los textos en la UI y regenerar una sección. Exportar a PDF con diseño profesional y, como extra opcional, IoCs a CSV y hallazgos a JSON.

# CRITERIOS DE ACEPTACIÓN CON EL EXCEL DE EJEMPLO (solo para validar, NO para hardcodear)

Al cargar el archivo de ejemplo, la app debería surgir por sí misma, a partir de las reglas generales, con señales como: ráfagas de fallos desde IPs externas con un inicio exitoso después; una sesión administrativa originada en una IP externa con PowerShell codificado, reconocimiento (`whoami`, `net view`), acceso a shares, compresión de datos y conexión saliente; persistencia con tarea programada y servicio nuevo más ejecuciones periódicas de un binario en ProgramData; actividad web contra un servidor IIS con `?cmd=whoami` y ráfagas de 404/500; subidas repetidas y voluminosas a un destino externo vía proxy; lectura masiva de archivos de Finance; `vssadmin delete shadows`; compresión de documentos de Legal. Verifica tú mismo contra los datos cuáles de estas señales existen realmente y cuáles no, e informa las que no encuentres. Los eventos benignos (logons/logoffs normales, explorer.exe, servicios) no deben inflarse como hallazgos. Y tampoco debe haber hallazgos sin filas de evidencia.

# FORMA DE TRABAJO (importante, sigue este orden)

Contexto: trabajo con modelos gratuitos y soy principiante. Por eso: tareas pequeñas, una fase por sesión, comandos explicados, y verificación obligatoria al cerrar cada fase.

0. **Preflight y preguntas.** Haz el chequeo de solo lectura de la sección PREFLIGHT y léete el Excel de ejemplo. Después haz, en un solo mensaje numerado, todas las preguntas que necesites (cada una con tu propuesta por defecto para que yo solo confirme o corrija). No empieces a trabajar hasta que te responda. Si surgen dudas nuevas durante el trabajo, pregúntame en lugar de adivinar.
1. **Plan (sin código).** Con mis respuestas, y sin escribir archivos, preséntame en el chat: stack final, arquitectura y estructura de carpetas, modelo de datos normalizado, lista de reglas de detección con sus campos requeridos, y el plan por fases, donde cada fase tenga un criterio de "terminado" que yo pueda verificar abriendo la app. Espera mi OK.
2. **Documentos base.** Cuando yo te cambie a modo de construcción, crea: `docs/PLAN.md` (el plan aprobado), `AGENTS.md` en la raíz (contexto, convenciones, regla de rigor analítico, cómo ejecutar y probar) y `docs/PROGRESS.md` (fase actual, qué está hecho, qué sigue, decisiones tomadas). Actualiza `docs/PROGRESS.md` al cerrar cada fase: es tu memoria entre sesiones. Crea el `.gitignore` según la sección GIT Y GITHUB y copia ahí mismo las reglas de Git a `AGENTS.md`.
3. **Implementa por fases pequeñas y verificables:** (a) ingesta + normalización + tabla, (b) motor de reglas + tests, (c) correlación e incidentes + scoring, (d) dashboard, (e) IA + validación anti-alucinación, (f) informe + PDF, (g) pulido de UI, README y manejo de errores. Implementa SOLO la fase que yo te indique.
4. **Tests automáticos** (pytest) para cada regla con datos sintéticos pequeños, para la normalización de columnas, y un test de integración con el Excel de ejemplo. No des una fase por terminada sin ejecutar los tests y arrancar la app.
5. **Al cerrar cada fase** dime: qué quedó hecho, cómo ejecutarlo, cómo verificarlo yo paso a paso (qué abrir, qué probar, qué resultado debo ver), y qué sigue. Luego sugiere el mensaje de commit.
6. **Seguridad de la propia app:** validación de tamaño y tipo de archivo, sin ejecutar macros ni fórmulas del Excel, sanitizar todo lo que se renderiza (los logs pueden contener HTML/JS malicioso, por ejemplo URIs de webshells), sin secretos en el repo, y CORS/host restringido a localhost.
