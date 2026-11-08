# api/routes_report.py - Endpoints de la fase F: informe completo, edicion de
# secciones, PDF (Playwright/Chromium local) y exportaciones CSV/JSON.
# PLAN seccion 9 y 11: sin texto inventado, evidencia con Log_ID, CSV protegido
# contra inyeccion de formulas y archivos temporales en data/exports (git-ignorada).
import uuid
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Body, HTTPException, Query
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from starlette.background import BackgroundTask

from app.core import config
from app.reporting import exports as exports_mod
from app.reporting import report as report_mod
from app.reporting.pdf import render_report_pdf

router = APIRouter(prefix="/api", tags=["report"])


def _get_analysis(session_id: str, sheet: Optional[str]):
    from app.services import sessions as store

    s = store.get_session(session_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Sesion no encontrada o expirada.")
    target = sheet or next(iter(s.analyses), None)
    if target is None or target not in s.analyses:
        raise HTTPException(
            status_code=404,
            detail="Esta sesion aun no tiene analisis. Ejecuta /analyze primero.",
        )
    return s, target, s.analyses[target]


@router.get("/sessions/{session_id}/report")
def session_report(session_id: str, sheet: Optional[str] = Query(None)) -> Any:
    """Informe completo (PLAN sección 9) con las ediciones del analista aplicadas."""
    s, _, result = _get_analysis(session_id, sheet)
    rep = report_mod.build_report(result)
    rep["session_id"] = session_id
    rep["file_name"] = s.file_name
    return rep


class SectionEditRequest(BaseModel):
    text: str


class ReportMetaRequest(BaseModel):
    cliente: Optional[str] = None
    analista: Optional[str] = None


@router.put("/sessions/{session_id}/report/meta")
def set_report_meta(session_id: str, req: ReportMetaRequest = Body(...), sheet: Optional[str] = Query(None)) -> Any:
    """Guarda los datos editables de la portada (cliente y analista)."""
    _, _, result = _get_analysis(session_id, sheet)
    from app.reporting.report import set_report_meta as _set

    meta = _set(result, cliente=req.cliente, analista=req.analista)
    return {"ok": True, "meta": meta}


@router.put("/sessions/{session_id}/report/sections/{section_id}")
def edit_section(
    session_id: str,
    section_id: str,
    req: SectionEditRequest = Body(...),
    sheet: Optional[str] = Query(None),
) -> Any:
    """Edita una seccion del informe (etiquetas opcionales 'Hecho:'/'Inferencia:'/'Hipotesis:')."""
    _, _, result = _get_analysis(session_id, sheet)
    try:
        report_mod.apply_section_edit(result, section_id, req.text)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"La seccion '{section_id}' no existe en el informe.")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    rep = report_mod.build_report(result)
    section = next((s for s in rep["sections"] if s["section_id"] == section_id), None)
    return {"ok": True, "section": section}


@router.post("/sessions/{session_id}/report/sections/{section_id}/regenerate")
def regenerate_section(
    session_id: str,
    section_id: str,
    sheet: Optional[str] = Query(None),
) -> Any:
    """Restaura una seccion a su contenido base (plantilla/narrativa validada)."""
    _, _, result = _get_analysis(session_id, sheet)
    try:
        section = report_mod.regenerate_section(result, section_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"La seccion '{section_id}' no existe en el informe.")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True, "section": section}


@router.get("/sessions/{session_id}/report/pdf")
def report_pdf(session_id: str, sheet: Optional[str] = Query(None)) -> Any:
    """Genera el PDF A4 del informe (portada, indice, numeracion, tablas y evidencia)."""
    s, target, result = _get_analysis(session_id, sheet)
    rep = report_mod.build_report(result)
    rep["file_name"] = s.file_name
    out_path = config.EXPORT_DIR / f"tmp_informe_{uuid.uuid4().hex}.pdf"
    try:
        try:
            render_report_pdf(rep, out_path)
        except Exception as exc:  # mensaje claro en espanol, sin trazas internas
            if out_path.exists():
                try:
                    out_path.unlink()
                except OSError:
                    pass
            raise HTTPException(
                status_code=500,
                detail="No se pudo generar el PDF del informe. Verifica que el Chromium de "
                       f"Playwright este instalado (.venv: playwright install chromium). Detalle: {exc}",
            )
        if not out_path.exists() or out_path.stat().st_size == 0:
            raise HTTPException(status_code=500, detail="El PDF generado esta vacio.")

        safe_name = Path(s.file_name or "informe.xlsx").stem
        download_name = f"informe_{safe_name}_{target}.pdf"

        def _cleanup(path: Path) -> None:
            try:
                path.unlink()
            except OSError:
                pass

        return FileResponse(
            path=out_path,
            media_type="application/pdf",
            filename=download_name,
            background=BackgroundTask(_cleanup, out_path),
        )
    finally:
        pass


@router.get("/sessions/{session_id}/exports/iocs.csv")
def export_iocs_csv(session_id: str, sheet: Optional[str] = Query(None)) -> Any:
    """IoCs a CSV (con proteccion contra inyeccion de formulas)."""
    s, target, result = _get_analysis(session_id, sheet)
    csv_text = exports_mod.iocs_csv(result)
    return Response(
        content=csv_text.encode("utf-8-sig"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="iocs_{target}.csv"'},
    )


@router.get("/sessions/{session_id}/exports/findings.json")
def export_findings_json(session_id: str, sheet: Optional[str] = Query(None)) -> Any:
    """Hallazgos a JSON (estructura determinista del motor)."""
    _, target, result = _get_analysis(session_id, sheet)
    payload = exports_mod.findings_json(result)
    return Response(
        content=payload.encode("utf-8"),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="hallazgos_{target}.json"'},
    )
