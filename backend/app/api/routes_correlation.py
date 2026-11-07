# api/routes_correlation.py - Endpoints de la fase C: incidentes y override manual.
# PLAN 6.4 y 7: incidentes con timeline/IoCs/MITRE/kill chain y override con motivo obligatorio.
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, HTTPException, Query
from pydantic import BaseModel, Field

from app.correlation.loader import load_config_cached

router = APIRouter(prefix="/api", tags=["correlation"])


def _get_analysis(session_id: str, sheet: Optional[str]):
    from app.services import sessions as store

    s = store.get_session(session_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Sesion no encontrada o expirada.")
    target = sheet or next(iter(s.analyses), None)
    if target is None or target not in s.analyses:
        raise HTTPException(status_code=404, detail="Esta sesion aun no tiene analisis. Ejecuta /analyze primero.")
    return s, target, s.analyses[target]


class OverrideRequest(BaseModel):
    target_type: str = Field(description="'finding' o 'incident'")
    target_id: str = Field(min_length=1)
    classification: str = Field(min_length=1)
    reason: str = Field(min_length=1)


@router.get("/sessions/{session_id}/incidents")
def session_incidents(session_id: str, sheet: Optional[str] = Query(None)) -> Any:
    """Incidentes correlacionados con timeline, IoCs, MITRE, kill chain y relaciones."""
    _, _, result = _get_analysis(session_id, sheet)
    corr = result.correlation or {}
    incidents = [dict(inc) for inc in corr.get("incidents", [])]
    for inc in incidents:
        ov = result.overrides.get(f"incident:{inc.get('incident_id')}")
        if ov:
            inc["override"] = ov
    relations = list(corr.get("relations", []))
    # Anota tambien el override en las relaciones para que la UI lo muestre.
    for rel in relations:
        rel["overrides"] = [
            result.overrides[f"incident:{iid}"]
            for iid in rel.get("incidents", [])
            if f"incident:{iid}" in result.overrides
        ]
    return {
        "session_id": session_id,
        "sheet": result.sheet,
        "summary": corr.get("summary", {}),
        "incidents": incidents,
        "relations": relations,
    }


@router.post("/sessions/{session_id}/overrides")
def create_override(session_id: str, req: OverrideRequest = Body(...)) -> Any:
    """Override manual de clasificacion (hallazgo o incidente) con motivo obligatorio.

    Conserva el score automatico (PLAN 7): el override anade la clasificacion manual.
    """
    s, _, result = _get_analysis(session_id, None)
    cfg = load_config_cached()

    ttype = req.target_type.strip().casefold()
    if ttype not in ("finding", "incident"):
        raise HTTPException(status_code=400, detail="target_type debe ser 'finding' o 'incident'.")
    classification = req.classification.strip()
    if classification not in cfg.override_classifications:
        raise HTTPException(
            status_code=400,
            detail=f"classification debe ser una de: {', '.join(cfg.override_classifications)}.",
        )
    reason = req.reason.strip()
    if not reason:
        raise HTTPException(status_code=400, detail="El motivo del override es obligatorio.")
    if len(reason) > cfg.override_max_reason_chars:
        raise HTTPException(
            status_code=400,
            detail=f"El motivo no puede superar {cfg.override_max_reason_chars} caracteres.",
        )

    # El objetivo debe existir en el analisis actual.
    if ttype == "finding":
        exists = any(
            f.get("finding_id") == req.target_id
            for f in (result.detection or {}).get("findings", [])
        )
    else:
        exists = any(
            inc.get("incident_id") == req.target_id
            for inc in (result.correlation or {}).get("incidents", [])
        )
    if not exists:
        raise HTTPException(status_code=404, detail=f"No existe {ttype} '{req.target_id}' en este analisis.")

    override = {
        "target_type": ttype,
        "target_id": req.target_id,
        "classification": classification,
        "reason": reason,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "file_name": s.file_name,
    }
    result.overrides[f"{ttype}:{req.target_id}"] = override
    return {"ok": True, "override": override}
