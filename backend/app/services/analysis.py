# services/analysis.py - Pipeline de analisis (fase A): mapa -> normaliza -> calidad.
from typing import Any, Dict, List, Optional

from app.ingestion import aliases as aliases_mod
from app.ingestion import quality as quality_mod
from app.ingestion import validator
from app.ingestion.mapping import suggest_mapping, validate_mapping
from app.ingestion.normalize import build_event
from app.services.sessions import AnalysisResult, SessionData


def run_analysis(
    session: SessionData,
    sheet: str,
    header_row: int,
    mapping_entries: List[Dict[str, Optional[str]]],
) -> AnalysisResult:
    if sheet not in session.sheets:
        raise validator.UploadError(f"La hoja '{sheet}' no existe en el archivo.")
    sheet_data = session.sheets[sheet]

    header_idx = header_row - 1
    if header_idx == sheet_data.header_row_idx:
        columns = sheet_data.columns
        rows = sheet_data.rows
    else:
        raw_all = _rebuild_rows(session, sheet)
        if header_idx < 0 or header_idx >= len(raw_all):
            raise validator.UploadError("La fila de cabecera indicada no existe en la hoja.")
        from app.ingestion.mapping import build_columns

        max_col = max(len(r) for r in raw_all[header_idx : header_idx + 2])
        columns = build_columns(raw_all[header_idx], max_col)
        rows = [r for r in raw_all[header_idx + 1 :]]
        rows = [
            r + [None] * (len(columns) - len(r)) if len(r) < len(columns) else r
            for r in rows
        ]

    field_map, log_id_column = validate_mapping(mapping_entries, columns)

    events: List[Dict[str, Any]] = []
    for n, row in enumerate(rows, start=1):
        event = build_event(
            row=row,
            field_map=field_map,
            sheet_name=sheet,
            row_number=n,
            log_id_column=log_id_column,
        )
        if log_id_column is None:
            event["log_id"] = f"ROW-{n}"
            event["quality_flags"].append("log_id_synthetic")
        # Si no viene fila completa (fila vacia), se marca y se mantiene como evidencia.
        raw_cells = [c for c in row if c not in (None, "")]
        if not raw_cells:
            event["quality_flags"].append("empty_row")
            continue
        events.append(event)

    if not events:
        raise validator.UploadError("La hoja no contiene filas de datos legibles.")

    host_vals = [e.get("host_raw") for e in events]
    user_vals = [e.get("user_raw") for e in events]

    q = quality_mod.summarize(events)
    q["mixed_type_columns"] = quality_mod.mixed_type_columns(columns, rows)

    result = AnalysisResult(
        sheet=sheet,
        header_row_idx=header_idx,
        columns=columns,
        field_map=field_map,
        log_id_column=log_id_column,
        events=events,
        quality=q,
    )
    result.quality["aliases"] = aliases_mod.build_alias_report(host_vals, user_vals)

    # Fase B: motor determinista de deteccion sobre los eventos normalizados.
    from app.detection.engine import run_detection

    result.detection = run_detection(events)

    # Fase C: scoring de hallazgos + correlacion en incidentes (PLAN 6.4 y 7).
    from app.correlation.correlator import run_correlation
    from app.correlation.loader import load_config_cached
    from app.correlation.scoring import score_findings

    cfg = load_config_cached()
    score_findings(result.detection.get("findings", []), cfg)
    result.correlation = run_correlation(result.detection.get("findings", []), events, cfg)

    session.analyses[sheet] = result
    return result


def _rebuild_rows(session: SessionData, sheet: str) -> List[List[Any]]:
    """Relee la hoja completa desde el archivo guardado (para cambio de cabecera)."""
    import openpyxl

    wb = openpyxl.load_workbook(session.file_path, read_only=True, data_only=True)
    try:
        if sheet not in wb.sheetnames:
            raise validator.UploadError(f"La hoja '{sheet}' ya no existe en el archivo.")
        ws = wb[sheet]
        rows = [list(r) for r in ws.iter_rows(values_only=True)]
        return rows
    finally:
        wb.close()


def mapping_preview_for_sheet(session: SessionData, sheet: str) -> List[Dict[str, Any]]:
    return session.suggestions.get(sheet, suggest_mapping(session.sheets[sheet].columns))
