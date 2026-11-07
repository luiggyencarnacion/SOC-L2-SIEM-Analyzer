# PROGRESS.md — Estado del proyecto

Última actualización: fase 0 en curso.

## Estado por fase

| Fase | Estado | Notas |
|---|---|---|
| 0 | en curso | Se han creado `docs/PLAN.md`, `AGENTS.md`, `docs/PROGRESS.md` y `.gitignore`. Falta esqueleto de `start.ps1`/`test.ps1` (después de aprobación de dependencias). |
| A | pendiente | Ingesta + normalización + tabla. |
| B1 | pendiente | Reglas AUTH-001–005, AUTH-007, PRIV-001/002, EXEC-001–007, PERS-001–003. |
| B2 | pendiente | Reglas LAT-001–004, EXF-001–004, WEB-001–003. |
| C | pendiente | Correlación, incidentes, scoring y override. |
| D | pendiente | Dashboard interactivo. |
| E | pendiente | Plantillas deterministas + IA (sin chat). |
| F | pendiente | Informe completo y PDF. |
| F2 | pendiente | Chat IA sobre el caso. |
| G | pendiente | Pulido, README, errores, rendimiento, seguridad. |
| H (opcional) | pendiente | AUTH-006, AUTH-008, BASE-001, BASE-002. |

## Decisiones tomadas

- Plan aprobado con correcciones de LAT-001 (ancla a acceso externo/RDP), AUTH-001 absorbido por AUTH-002, bands de scoring coherentes y `EXEC-004`/`WEB-003` base Crítico.
- `.\start.ps1` y `.\test.ps1` unificados en la raíz.
- IA por defecto `none`; claves solo en `.env`; chat tras F (F2).
- Sin hardcoding del ejemplo; reglas genéricas con umbrales configurables.

## Pendientes inmediatos

- Aprobar la lista concreta de dependencias a instalar (Python + Node) antes de crear el esqueleto de backend/frontend.
- Añadir `.env.example` y `README.md` cuando el esqueleto arranque.
- Crear `start.ps1` y `test.ps1` en la raíz solo cuando exista algo que ejecutar.

## Recordatorios

- Regla de oro: todo hallazgo debe tener evidencia con `Log_ID`; si no, frase exacta “No hay evidencia en los logs proporcionados.”
- Reglas de Git en `AGENTS.md` deben respetarse antes de cualquier commit.
