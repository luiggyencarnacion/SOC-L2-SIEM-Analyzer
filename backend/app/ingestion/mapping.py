# ingestion/mapping.py - Deteccion automatica de cabecera y mapeo a campos universales.
# Los sinonimos son genericos (nombres de columna habituales), no valores del ejemplo.
import re
from typing import Any, Dict, List, Optional, Tuple

from app.ingestion.validator import UploadError

# Sinonimos GENERICOS por campo universal (PLAN seccion 6.1 abreviados).
FIELD_SYNONYMS: Dict[str, Tuple[str, ...]] = {
    "log_id": ("log_id", "logid", "log id", "id_log", "id", "event_id_log"),
    "ts": ("timestamp", "fecha", "hora", "date", "time", "eventtime", "datetime"),
    "host": ("hostname", "host name", "host", "computer", "computername", "equipo", "servidor", "maquina", "pc_name"),
    "user": ("user", "username", "user name", "usuario", "cuenta", "account", "accountname"),
    "src_ip": ("source ip", "sourceip", "src ip", "srcip", "ip origen", "ip_source", "origin ip", "client_ip"),
    "dst": ("destination", "destino", "dest", "target", "url", "remote", "remoteip"),
    "event_code": ("event id", "eventid", "event_id", "evento", "event code", "codigoevento", "code"),
    "msg": ("event description", "description", "descripcion", "message", "mensaje", "msg", "detalle", "summary"),
    "cmd": ("process commandline", "commandline", "command", "cmd", "comando", "process"),
    "result": ("result", "resultado", "status", "estado", "outcome"),
    "log_source": ("log source", "logsource", "fuente", "channel", "canal", "provider", "providername"),
    "sev_siem": ("severity", "severidad", "level", "nivel", "priority"),
    "logon_type": ("logon type", "logontype", "tipo de logon", "logontypeid"),
    "http": ("http status", "httpstatus", "statuscode", "web method", "http method"),
    "share": ("share", "recurso compartido", "sharename", "smb"),
    "file_path": ("file path", "filepath", "ruta", "path", "file", "archivo", "nombrearchivo"),
    "bytes_out": ("bytes out", "bytesout", "data out", "bytes", "tamano", "size"),
    "task_service": ("task name", "taskname", "servicio", "service name", "servicename", "tarea"),
}


def _clean(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value if value is not None else "")).strip()


def _norm_name(value: Any) -> str:
    """Nombre de columna normalizado para comparar sin ambiguedades."""
    lowered = _clean(value).lower()
    return re.sub(r"[\s_-]+", " ", lowered).strip()


def detect_header_row(rows: List[List[Any]]) -> int:
    """Detecta la fila de cabecera: la primera fila con la mayor proporcion
    de celdas de texto no vacias entre las primeras 15 filas."""
    best_idx, best_score = 0, -1.0
    for idx, row in enumerate(rows[:15]):
        if all(c is None for c in row):
            continue
        cells = [_clean(c) for c in row]
        nonempty = [c for c in cells if c]
        if not nonempty:
            continue
        text_share = sum(1 for c in nonempty if not _looks_numeric(c)) / len(cells)
        filled_share = len(nonempty) / max(1, len([c for c in row if c is not None]))
        score = text_share + filled_share
        if score > best_score:
            best_idx, best_score = idx, score
    return best_idx


def _looks_numeric(text: str) -> bool:
    try:
        float(text.replace(",", "."))
        return True
    except ValueError:
        return False


def build_columns(header: List[Any], max_col: int) -> List[str]:
    """Nombres de columna; sin nombre -> Columna N; duplicados -> sufijo (2)."""
    names: List[str] = []
    seen: Dict[str, int] = {}
    for i in range(max_col):
        raw = _clean(header[i]) if i < len(header) else ""
        name = raw or f"Columna {i + 1}"
        base = name
        count = seen.get(base, 0)
        if count:
            name = f"{base} ({count + 1})"
        seen[base] = count + 1
        names.append(name)
    return names


def suggest_mapping(columns: List[str]) -> List[Dict[str, Any]]:
    """Sugerencia de mapeo columna -> campo universal con confianza y motivo."""
    used_fields: Dict[str, str] = {}
    suggestions: List[Dict[str, Any]] = []
    for col in columns:
        normed = _norm_name(col)
        best_field, best_conf, best_why = None, 0.0, "sin coincidencia"
        for field, syns in FIELD_SYNONYMS.items():
            if field in used_fields:
                continue  # un campo solo puede tomar una columna
            score, why = _score(normed, syns)
            if score > best_conf:
                best_field, best_conf, best_why = field, score, why
        if best_field is not None:
            used_fields[best_field] = col
        suggestions.append(
            {
                "column": col,
                "field": best_field,
                "confidence": round(best_conf, 2),
                "rationale": best_why,
            }
        )
    return suggestions


def _score(normed: str, syns: Tuple[str, ...]) -> Tuple[float, str]:
    if not normed:
        return 0.0, "columna sin nombre"
    for syn in syns:
        if normed == syn:
            return 1.0, "coincidencia exacta con sinonimo estandar"
    for syn in syns:
        if len(syn) >= 4 and syn in normed:
            return 0.8, "contiene sinonimo estandar"
    tokens = set(normed.split())
    for syn in syns:
        stok = set(syn.split())
        if tokens & stok and len(tokens & stok) / len(stok) >= 0.5:
            return 0.6, "coincidencia parcial de palabras"
    return 0.0, "sin coincidencia"


def validate_mapping(
    mapping: List[Dict[str, Optional[str]]],
    columns: List[str],
) -> Tuple[Dict[str, int], Optional[str]]:
    """Convierte [{column, field}] en {campo: indice_de_columna}.
    Devuelve tambien el nombre de columna usado como log_id (o None)."""
    col_index = {c: i for i, c in enumerate(columns)}
    field_map: Dict[str, int] = {}
    log_id_column: Optional[str] = None
    for entry in mapping:
        col = (entry.get("column") or "").strip()
        field = entry.get("field") or None
        if field and col in col_index:
            if field in field_map:
                raise UploadError(f"El campo '{field}' esta asignado a mas de una columna.")
            field_map[field] = col_index[col]
            if field == "log_id":
                log_id_column = col
    if "ts" not in field_map:
        has_identity = any(f in field_map for f in ("user", "host", "src_ip"))
        if not has_identity:
            raise UploadError(
                "Estructura insuficiente: se necesita timestamp o al menos una identidad (usuario, host o IP)."
            )
    else:
        pass
    return field_map, log_id_column
