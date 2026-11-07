# ingestion/quality.py - Reporte de calidad de datos (fase A).
# Contenido (PLAN seccion 4.1): nulos, duplicados, tipos mezclados, alias,
# discrepancias de severidad, estado del timestamp, distribución de resultados.
from typing import Any, Dict, List

from app.ingestion.normalize import normalize_key

DISPLAY_FIELDS = [
    "timestamp_raw", "host_raw", "user_raw", "event_code", "event_description",
    "source_ip", "destination_raw", "log_source", "process_command_line",
    "result_raw", "severity_siem",
]
SOURCE_FIELDS = [
    "logon_type", "http_method", "http_status", "file_path", "bytes_out",
    "task_name", "service_name", "share", "url_path",
]


def summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(rows)
    columns: List[Dict[str, Any]] = []
    for field in DISPLAY_FIELDS + SOURCE_FIELDS:
        vals = [r.get(field) for r in rows]
        populated = [v for v in vals if v not in (None, "")]
        columns.append(
            {
                "column": field,
                "populated": len(populated),
                "nulls": total - len(populated),
                "null_percent": round(100.0 * (total - len(populated)) / total, 1) if total else 0.0,
                "distinct": len({str(v) for v in populated}),
            }
        )

    log_ids = [r.get("log_id") for r in rows if r.get("log_id") not in (None, "")]
    seen: Dict[str, int] = {}
    for lid in log_ids:
        seen[lid] = seen.get(lid, 0) + 1
    duplicates = sorted([k for k, v in seen.items() if v > 1])

    ts = {
        "total": total,
        "missing": 0,
        "invalid": 0,
        "wall": 0,
        "offset": 0,
    }
    result_dist: Dict[str, int] = {}
    for r in rows:
        status = r.get("timestamp_status")
        if status == "valid_wall":
            ts["wall"] += 1
        elif status == "valid_offset":
            ts["offset"] += 1
        elif status == "invalid":
            ts["invalid"] += 1
        else:
            ts["missing"] += 1
        norm = r.get("result_norm") or "other"
        result_dist[norm] = result_dist.get(norm, 0) + 1

    # Campos derivados desde texto libre (sin columna dedicada) -> se anotan.
    derived_columns = [
        {
            "column": "es_campos_extraidos_de_texto",
            "populated": sum(1 for r in rows if r.get("extracted")),
            "nulls": sum(1 for r in rows if not r.get("extracted")),
            "null_percent": round(100.0 * sum(1 for r in rows if not r.get("extracted")) / total, 1) if total else 0.0,
            "distinct": None,
        }
    ]

    mixed: List[str] = []

    return {
        "total_rows": total,
        "columns": columns + derived_columns,
        "duplicate_log_ids": duplicates,
        "timestamp": ts,
        "result_distribution": result_dist,
        "mixed_type_columns": mixed,
    }


def mixed_type_columns(columns: List[str], sheet_rows: List[List[Any]]) -> List[str]:
    """Columnas crudas cuyo valor contiene mas de un tipo python (mezcla de tipos)."""
    out: List[str] = []
    for idx, col in enumerate(columns):
        types: set = set()
        for row in sheet_rows:
            if len(row) <= idx:
                continue
            val = row[idx]
            if val is None or (isinstance(val, str) and not val.strip()):
                continue
            types.add(type(val).__name__)
            if len(types) > 1:
                break
        if len(types) > 1:
            out.append(col)
    return out


def duplicate_identity_values(rows: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """valores crudos repetidos para host/user (info de calidad)."""
    out: Dict[str, List[str]] = {"hosts": [], "users": []}
    for field, out_key in (("host_raw", "hosts"), ("user_raw", "users")):
        counter: Dict[str, int] = {}
        for r in rows:
            v = r.get(field)
            if v not in (None, ""):
                counter[v] = counter.get(v, 0) + 1
        out[out_key] = sorted([k for k, v in counter.items() if v > 1])
    return out
