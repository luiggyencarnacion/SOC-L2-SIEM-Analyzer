# api/routes_ingestion.py - Endpoints de la fase A.
import json
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, File, HTTPException, Query, UploadFile

from app.core import config
from app.detection import loader as rules_loader
from app.ingestion import validator
from app.ingestion.mapping import (
    build_columns,
    detect_header_row,
    suggest_mapping,
)
from app.models.schemas import (
    AliasReport,
    AnalyzeRequest,
    DataQualityReport,
    EventsResponse,
    SessionInfo,
    SheetPreview,
    SheetMapping,
    UploadResponse,
)
from app.services import analysis
from app.services.sessions import SheetData
from app.services import sessions as store
from app.services.stats import in_time_range, time_bounds

router = APIRouter(prefix="/api", tags=["ingestion"])


class UploadErrorHTTP(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=400, detail=detail)


def _extract_from_message(detail: Any) -> str:
    return str(detail)


# ---------- PREVIEW por hoja ----------

def build_sheet_preview(name: str, rows: List[List[Any]]) -> SheetPreview:
    header_idx = detect_header_row(rows)
    width = max(1, max((len(r) for r in rows), default=1))
    columns = build_columns(rows[header_idx], width)
    body_idx = header_idx + 1
    body = [r for r in rows[body_idx:] if any(c not in (None, "") for c in r)]
    body = body[: config.MAX_ROWS]
    previews = [dict(zip(columns, r + [None] * (len(columns) - len(r)))) for r in body[:5]]
    return SheetPreview(
        name=name,
        data_rows=len(body),
        data_columns=len(columns),
        header_row=header_idx + 1,
        columns=columns,
        preview_rows=previews,
    )


@router.post("/upload", response_model=UploadResponse)
async def upload_file(file: UploadFile = File(...)) -> Any:
    try:
        raw_data = await file.read()
        safe_name = validator.validate_extension(file.filename or "archivo.xlsx")
        validator.validate_signature_and_size(raw_data)
        validator.validate_no_macros(raw_data)
        sheets_cells = validator.load_workbook_sheets(raw_data)
    except validator.UploadError as exc:
        raise UploadErrorHTTP(_extract_from_message(exc))
    sheets: Dict[str, Any] = {}
    suggestions: Dict[str, List[Dict[str, Any]]] = {}
    warnings: List[str] = []
    previews: List[SheetPreview] = []
    mappings: List[SheetMapping] = []

    for name, rows in sheets_cells.items():
        header_idx = detect_header_row(rows)
        width = max(1, max((len(r) for r in rows), default=1))
        columns = build_columns(rows[header_idx], width)
        body_idx = header_idx + 1
        body = [r for r in rows[body_idx:] if any(c not in (None, "") for c in r)]
        if len(body) > config.MAX_ROWS:
            warnings.append(f"Lote limitado: la hoja '{name}' tiene mas de {config.MAX_ROWS} filas; solo se ingesta el limite.")
        body = body[: config.MAX_ROWS]
        sheets[name] = SheetData(
            name=name,
            header_row_idx=header_idx,
            columns=columns,
            rows=body,
            preview_rows=body[:5],
        )
        sug = suggest_mapping(columns)
        suggestions[name] = sug
        conf = sum(s["confidence"] for s in sug) / len(sug) if sug else 0.0
        previews.append(
            SheetPreview(
                name=name,
                data_rows=len(body),
                data_columns=len(columns),
                header_row=header_idx + 1,
                columns=columns,
                preview_rows=[dict(zip(columns, r + [None] * (len(columns) - len(r)))) for r in body[:5]],
            )
        )
        mappings.append(
            SheetMapping(
                sheet=name,
                header_row=header_idx + 1,
                suggestions=sug,
                confidence=round(conf, 2),
            )
        )
        warnings.extend(validator.check_min_structure(columns, len(body)))

    import pathlib

    upload_dir = config.UPLOAD_DIR
    upload_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = upload_dir / f"{uuid.uuid4()}.xlsx"
    tmp_path.write_bytes(raw_data)

    session = store.create_session(
        file_name=safe_name,
        file_path=tmp_path,
        size_bytes=len(raw_data),
        sheets=sheets,
        suggestions=suggestions,
        warnings=warnings,
    )

    return {
        "session_id": session.session_id,
        "file_name": session.file_name,
        "size_bytes": session.size_bytes,
        "sheets": previews,
        "mappings": mappings,
        "warnings": session.warnings,
    }


@router.get("/sessions/{session_id}", response_model=SessionInfo)
def session_info(session_id: str) -> Any:
    s = store.get_session(session_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Sesion no encontrada o expirada.")
    return {
        "session_id": s.session_id,
        "file_name": s.file_name,
        "size_bytes": s.size_bytes,
        "sheets": list(s.sheets.keys()),
        "analyzed": {name: len(r.events) for name, r in s.analyses.items()},
    }


@router.delete("/sessions/{session_id}")
def delete_session(session_id: str) -> Any:
    if not store.delete_session(session_id):
        raise HTTPException(status_code=404, detail="Sesion no encontrada o expirada.")
    return {"deleted": True, "session_id": session_id}


@router.post("/sessions/{session_id}/analyze")
async def analyze_sheet(session_id: str, req: AnalyzeRequest = Body(...)) -> Any:
    s = store.get_session(session_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Sesion no encontrada o expirada.")
    try:
        result = analysis.run_analysis(
            session=s,
            sheet=req.sheet,
            header_row=req.header_row,
            mapping_entries=[e.model_dump() for e in req.mapping],
        )
    except validator.UploadError as exc:
        raise UploadErrorHTTP(_extract_from_message(exc))
    sheet_warnings = warnings_for_mapping(result)
    quality_out = dict(result.quality)
    aliases = quality_out.pop("aliases", {"hosts": [], "users": []})
    return {
        "session_id": session_id,
        "sheet": req.sheet,
        "total_rows": len(result.events),
        "quality": quality_out,
        "aliases": aliases,
        "warnings": sheet_warnings,
        "detection_summary": (result.detection or {}).get("summary", {}),
    }


def warnings_for_mapping(result: analysis.AnalysisResult) -> Any:
    out: List[str] = []
    if result.log_id_column is None:
        out.append("Sin columna Log_ID mapeada; se asignan identificadores sinteticos ROW-N (con flag de calidad).")
    if not result.field_map.get("ts"):
        out.append("Sin columna de timestamp mapeada; el eje temporal quedara vacio.")
    if not any(k in result.field_map for k in ("user", "host", "src_ip")):
        out.append("Sin columnas de identidad mapeadas; no se podran generar alias.")
    return out


@router.get("/sessions/{session_id}/aliases", response_model=AliasReport)
def session_aliases(session_id: str, sheet: Optional[str] = Query(None)) -> Any:
    s = store.get_session(session_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Sesion no encontrada o expirada.")
    names = [sheet] if sheet else list(s.analyses.keys())
    if not names:
        raise HTTPException(status_code=404, detail="Esta sesion aun no tiene analisis.")
    hosts: List[Any] = []
    users: List[Any] = []
    for n in names:
        r = s.analyses.get(n)
        if r is None:
            continue
        report = r.quality.get("aliases") or {}
        hosts.extend(report.get("hosts", []))
        users.extend(report.get("users", []))
    return {"hosts": hosts, "users": users}


@router.get("/sessions/{session_id}/quality", response_model=DataQualityReport)
def session_quality(session_id: str, sheet: Optional[str] = Query(None)) -> Any:
    s = store.get_session(session_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Sesion no encontrada o expirada.")
    target = sheet or next(iter(s.analyses), None)
    if target is None or target not in s.analyses:
        raise HTTPException(status_code=404, detail="Esta sesion aun no tiene analisis.")
    return s.analyses[target].quality


# ---------- Tabla de eventos ----------

# Campos de la tabla de eventos que aceptan filtro por columna (coinciden con la UI).
FILTERABLE_FIELDS = (
    "log_id", "timestamp_raw", "timestamp_parsed", "host_raw", "host_key",
    "user_raw", "user_key", "event_code", "event_description", "source_ip",
    "source_ip_scope", "destination_raw", "destination_host", "destination_ip",
    "log_source", "process_command_line", "result_raw", "result_norm",
    "severity_siem", "logon_type", "http_status", "url_path", "share",
    "file_path", "quality_flags",
)

FILTER_FIELD_ALIASES: Dict[str, str] = {
    "timestamp": "timestamp_raw",
    "host": "host_raw",
    "user": "user_raw",
    "src_ip": "source_ip",
    "dst": "destination_raw",
    "event_code": "event_code",
    "result": "result_raw",
}


def _event_value(row: Dict[str, Any], field: str) -> str:
    raw = row.get(field)
    if field == "quality_flags":
        return " ".join(raw or [])
    return "" if raw is None else str(raw)


def _filter_rows(
    rows: List[Dict[str, Any]],
    q: Optional[str],
    sort: Optional[str],
    direction: str,
    filters: Dict[str, str],
    columns: List[str],
    from_dt: Any = None,
    to_dt: Any = None,
) -> List[Dict[str, Any]]:
    out = rows
    if from_dt is not None or to_dt is not None:
        # Rango temporal sobre timestamp_parsed (fase D); los eventos sin
        # timestamp valido quedan fuera del resultado filtrado.
        out = [r for r in out if in_time_range(r, from_dt, to_dt)]
    if q:
        needle = q.casefold()
        out = [
            r for r in out
            if any(
                needle in _event_value(r, f).casefold()
                for f in ("log_id", "timestamp_raw", "host_raw", "user_raw",
                          "event_code", "event_description", "source_ip",
                          "destination_raw", "log_source", "result_raw",
                          "severity_siem", "process_command_line", "share",
                          "file_path", "url_path")
            )
        ]
    for raw_col, text in filters.items():
        field = FILTER_FIELD_ALIASES.get(raw_col, raw_col)
        if field not in FILTERABLE_FIELDS:
            # columna cruda Legitima? traducir por nombre de columna del archivo.
            if raw_col in columns:
                continue  # el filtro por columna cruda necesita mapeo; se ignora de forma segura
            raise HTTPException(status_code=400, detail=f"Campo de filtro no admitido: '{raw_col}'.")
        needle = text.casefold()
        out = [r for r in out if needle in _event_value(r, field).casefold()]
    if sort:
        reverse = direction == "desc"

        def sort_key(r: Dict[str, Any]) -> Any:
            val = r.get(sort)
            if val is None:
                return (1, 0)
            try:
                return (0, float(val))
            except (TypeError, ValueError):
                return (0, str(val).casefold())

        out = sorted(out, key=sort_key, reverse=reverse)
    return out


@router.get("/sessions/{session_id}/events", response_model=EventsResponse)
def get_events(
    session_id: str,
    sheet: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    q: Optional[str] = Query(None),
    sort: Optional[str] = Query(None),
    direction: str = Query("asc"),
    filters: Optional[str] = Query(None),  # JSON {"columna": "texto"}
    time_from: Optional[str] = Query(None),  # ISO 8601; filtro temporal fase D
    time_to: Optional[str] = Query(None),  # ISO 8601 inclusive
) -> Any:
    s = store.get_session(session_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Sesion no encontrada o expirada.")
    target = sheet or next(iter(s.analyses), None)
    if target is None or target not in s.analyses:
        raise HTTPException(status_code=404, detail="Esta sesion aun no tiene analisis. Ejecuta /analyze primero.")
    result = s.analyses[target]
    try:
        from_dt, to_dt = time_bounds(time_from, time_to)
    except ValueError:
        raise HTTPException(status_code=400, detail="Los limites temporales deben ser fechas ISO 8601 validas.")
    parsed_filters: Dict[str, str] = {}
    if filters:
        try:
            data = json.loads(filters)
            if isinstance(data, dict):
                parsed_filters = {str(k): str(v) for k, v in data.items()}
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="El filtro debe ser JSON valido {'columna':'texto'}.")
    if direction not in ("asc", "desc"):
        raise HTTPException(status_code=400, detail="direction debe ser 'asc' o 'desc'.")
    rows = _filter_rows(result.events, q, sort, direction, parsed_filters, result.columns, from_dt, to_dt)
    start = (page - 1) * page_size
    end = start + page_size
    visible = [dict(r) for r in rows[start:end]]
    for r in visible:
        if r.get("raw") and isinstance(r["raw"], dict):
            r["raw"] = {"row": r["raw"].get("fields")}
    return {
        "session_id": session_id,
        "sheet": target,
        "total": len(rows),
        "page": page,
        "page_size": page_size,
        "rows": visible,
    }


# ---------- Deteccion (fase B) ----------

@router.get("/detection/rules")
def detection_rules() -> Any:
    """Catalogo de reglas cargadas desde el YAML (sin secretos ni datos del archivo)."""
    try:
        return {"rules": rules_loader.describe_rules()}
    except rules_loader.DetectionConfigError as exc:
        raise HTTPException(status_code=500, detail=f"Configuracion de reglas invalida: {exc}")


def _get_analysis(session_id: str, sheet: Optional[str]):
    s = store.get_session(session_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Sesion no encontrada o expirada.")
    target = sheet or next(iter(s.analyses), None)
    if target is None or target not in s.analyses:
        raise HTTPException(status_code=404, detail="Esta sesion aun no tiene analisis. Ejecuta /analyze primero.")
    return s, target, s.analyses[target]


@router.get("/sessions/{session_id}/findings")
def session_findings(
    session_id: str,
    sheet: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    rule: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
) -> Any:
    """Hallazgos del motor determinista con evidencia (Log_ID)."""
    _, _, result = _get_analysis(session_id, sheet)
    det = result.detection or {}
    findings = list(det.get("findings") or [])
    if severity:
        findings = [f for f in findings if f.get("severity", "").casefold() == severity.casefold()]
    if rule:
        findings = [f for f in findings if f.get("rule_id", "").casefold() == rule.casefold()]
    if q:
        needle = q.casefold()
        findings = [
            f for f in findings
            if needle in str(f).casefold()
        ]
    findings = [dict(f) for f in findings]
    for f in findings:
        ov = result.overrides.get(f"finding:{f.get('finding_id')}")
        if ov:
            f["override"] = ov
    return {
        "session_id": session_id,
        "sheet": result.sheet,
        "total": len(findings),
        "summary": det.get("summary", {}),
        "findings": findings,
    }


@router.get("/sessions/{session_id}/coverage")
def session_coverage(session_id: str, sheet: Optional[str] = Query(None)) -> Any:
    """Cobertura del motor: estado de cada regla y por que se omitio."""
    _, _, result = _get_analysis(session_id, sheet)
    det = result.detection or {}
    return {
        "session_id": session_id,
        "sheet": result.sheet,
        "summary": det.get("summary", {}),
        "coverage": det.get("coverage", []),
    }


@router.get("/sessions/{session_id}/events/{log_id}")
def get_single(session_id: str, log_id: str, sheet: Optional[str] = Query(None)) -> Any:
    s = store.get_session(session_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Sesion no encontrada o expirada.")
    target = sheet or next(iter(s.analyses), None)
    if target is None or target not in s.analyses:
        raise HTTPException(status_code=404, detail="Esta sesion aun no tiene analisis.")
    for r in s.analyses[target].events:
        if str(r.get("log_id")) == log_id:
            out = dict(r)
            out["raw"] = {"row": r.get("raw", {}).get("fields")}
            out["columns"] = s.analyses[target].columns
            return out
    raise HTTPException(status_code=404, detail=f"No hay evidencia en los logs proporcionados con Log_ID '{log_id}'.")
