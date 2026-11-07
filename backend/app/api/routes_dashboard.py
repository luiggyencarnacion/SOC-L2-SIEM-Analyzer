# api/routes_dashboard.py - Endpoint de agregados del dashboard (fase D).
# Calculo determinista desde los eventos y resultados ya en memoria (sesion).
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query

from app.services import sessions as store
from app.services.stats import build_stats

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/sessions/{session_id}/stats")
def session_stats(
    session_id: str,
    sheet: Optional[str] = Query(None),
    top_n: int = Query(10, ge=1, le=50),
) -> Any:
    """Resumen agregado del analisis para el dashboard (KPIs, series, tops).

    Los conteos se derivan unicamente de los eventos cargados y de los
    hallazgos del motor determinista; no hay IA ni valores fijados en codigo.
    """
    s = store.get_session(session_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Sesion no encontrada o expirada.")
    target = sheet or next(iter(s.analyses), None)
    if target is None or target not in s.analyses:
        raise HTTPException(status_code=404, detail="Esta sesion aun no tiene analisis. Ejecuta /analyze primero.")
    result = s.analyses[target]
    out = build_stats(result, top_n=top_n)
    out["session_id"] = session_id
    return out
