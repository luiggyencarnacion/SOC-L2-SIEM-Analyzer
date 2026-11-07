# ingestion/normalize.py - Normalizacion determinista (fase A).
# Politicas (PLAN seccion 4.2 y 4.3):
# - El valor crudo nunca se sobrescribe; la clave canonica va aparte (host_key/user_key).
# - Event_ID siempre texto; Result mapeado conservando el original.
# - Timestamps: se respeta el offset si existe; naive = hora de pared.
# - IPs validadas con ipaddress; clasificacion privada/publica/loopback/invalida.
# - Extraccion desde texto libre con regex; siempre marcada como "extraido del texto".
# - raw conserva la fila completa para evidencia.
import re
from datetime import datetime
from typing import Any, Dict, Optional, Tuple


# ----------------- Claves de identidades -----------------

def normalize_key(value: Any) -> str:
    """Clave canonica: minusculas y solo [a-z0-9]. Ej: 'DC-01' y 'DC01' -> dc01."""
    lowered = str(value if value is not None else "").lower()
    return re.sub(r"[^a-z0-9]+", "", lowered)


# ----------------- Timestamps -----------------

TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%d-%m-%Y %H:%M:%S",
)


def parse_timestamp(value: Any) -> Tuple[Optional[str], str]:
    """Devuelve (iso_string_o_None, status).

    status: missing | valid_wall (naive, se trata como hora de pared)
            | valid_offset (con zona horaria, offset respetado) | invalid.
    """
    if value is None:
        return None, "missing"
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if not text:
            return None, "missing"
        dt = None
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00").replace("z", "+00:00"))
        except ValueError:
            for fmt in TS_FORMATS:
                try:
                    dt = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
        if dt is None:
            return text, "invalid"
    if dt.tzinfo is not None:
        return dt.isoformat(), "valid_offset"
    return dt.isoformat(), "valid_wall"


# ----------------- Result / HTTP -----------------

SUCCESS_WORDS = {"success", "allowed", "ok", "true", "permitido", "exito", "conectado"}
FAILURE_WORDS = {"failure", "fail", "failed", "false", "denegado", "rechazado", "denied", "error de inicio", "logon failed"}
DENIED_WORDS = {"denied", "denegado", "acceso denegado", "unauthorized", "forbidden"}


def map_result(value: Any) -> Tuple[str, Optional[int]]:
    """Devuelve (result_norm, http_status). result_norm: success|failure|denied|error|other."""
    raw = "" if value is None else str(value).strip()
    if not raw:
        return "other", None
    if re.fullmatch(r"\d{3}", raw):
        code = int(raw)
        if 200 <= code <= 299:
            return "success", code
        if code in (401, 403):
            return "denied", code
        if 400 <= code <= 499:
            return "failure", code
        if 500 <= code <= 599:
            return "error", code
        return "other", code
    lowered = raw.lower()
    if lowered in SUCCESS_WORDS:
        return "success", None
    if lowered in DENIED_WORDS:
        return "denied", None
    if lowered in FAILURE_WORDS:
        return "failure", None
    if "error" in lowered or "fail" in lowered:
        return "error", None
    return "other", None


# ----------------- IPs -----------------

def validate_ip(value: Any) -> Tuple[Optional[str], Optional[str]]:
    """Devuelve (ip_norm, scope): scope private|public|loopback|reserved|invalid|None."""
    text = str(value if value is not None else "").strip()
    if not text:
        return None, None
    import ipaddress

    candidates = {text}
    match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", text)
    if match and match.group(1) != text:
        candidates.add(match.group(1))
    scope: Optional[str] = None
    norm: Optional[str] = None
    for cand in candidates:
        try:
            ip = ipaddress.ip_address(cand)
        except ValueError:
            continue
        norm = str(ip)
        if ip.is_loopback:
            scope = "loopback"
        elif ip.is_private:
            scope = "private"
        elif ip.is_reserved or ip.is_multicast or ip.is_link_local:
            scope = "reserved"
        else:
            scope = "public"
        break
    scope_out = scope if scope in ("public", "private", "loopback", "reserved") else (
        "invalid" if (not norm and candidates and text) else scope
    )
    return norm, scope_out


# ----------------- Extraccion desde texto libre -----------------

RE_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
RE_URL = re.compile(r"(?:(?:https?|ftp)://[^\s\"'<>]+)")
RE_DOMAIN_USER = re.compile(r"\b([A-Za-z0-9._-]+)\\([A-Za-z0-9._$-]+)\b")
RE_UNC = re.compile(r"\\\\[A-Za-z0-9._-]+\\[^\s\"';,]+")
RE_WIN_PATH = re.compile(r"\b(?:[A-Za-z]:\\(?:[^\\/:*?\"<>|\s]+\\?)*|\/(?:[\w.\-]+\/?)+)\b")
RE_LOGON_TYPE = re.compile(r"[Ll]ogon\s+[Tt]ype:\s*(\d+)")


def extract_from_text(text: Any) -> Dict[str, Any]:
    """Extrae IPs/URLs/cuentas/rutas/etc. desde texto libre."""
    s = str(text) if text is not None else ""
    out: Dict[str, Any] = {}
    if not s:
        return out
    ips = list(dict.fromkeys(RE_IP.findall(s)))
    if ips:
        out["ips"] = ips
    urls = list(dict.fromkeys(RE_URL.findall(s)))
    if urls:
        out["urls"] = urls
    m = RE_DOMAIN_USER.search(s)
    if m:
        out["domain_user"] = f"{m.group(1)}\\{m.group(2)}"
    uncs = list(dict.fromkeys(RE_UNC.findall(s)))
    if uncs:
        out["unc_paths"] = uncs
    paths = list(dict.fromkeys(RE_WIN_PATH.findall(s)))
    if paths:
        out["paths"] = paths
    m = RE_LOGON_TYPE.search(s)
    if m:
        out["logon_type"] = m.group(1)
    return out


def split_destination(value: Any) -> Dict[str, Any]:
    """Separa un destino generico en host/IP/puerto/URL."""
    s = str(value if value is not None else "").strip()
    out: Dict[str, Any] = {"destination_raw": s or None}
    if not s:
        return out
    m = re.match(r"^([A-Za-z-]+)://", s)
    if m:
        out["destination_host"] = s
        return out
    ip, scope = validate_ip(s)
    if ip:
        out["destination_ip"] = ip
        out["destination_scope"] = scope
        return out
    port_m = re.search(r":(\d{2,5})$", s)
    host = re.split(r"\s*\(.*\)\s*$", s)[0].strip()
    if port_m and not host.endswith(":"):
        out["destination_host"] = host[:-len(port_m.group(1))].rstrip(":") or host
        out["destination_port"] = int(port_m.group(1))
        out["destination_host"] = out["destination_host"]
    else:
        out["destination_host"] = host
    return out


# ----------------- Construcion del record -----------------

def build_event(
    row: Tuple[Any, ...],        # valores crudos de la fila
    field_map: Dict[str, int],   # campo universal -> indice
    sheet_name: str,
    row_number: int,
    log_id_column: Optional[int],
) -> Optional[Dict[str, Any]]:
    """Construye un EventRecord normalizado desde una fila cruda."""
    def raw(field: str) -> Any:
        idx = field_map.get(field)
        if idx is None or idx >= len(row):
            return None
        return row[idx]

    ts_raw = raw("ts")
    ts_iso, ts_status = parse_timestamp(ts_raw)
    user_raw = raw("user")
    host_raw = raw("host")
    src_raw = raw("src_ip")
    dst_raw = raw("dst")
    event_code = raw("event_code")
    msg_raw = raw("msg")
    cmd_raw = raw("cmd")
    result_raw = raw("result")
    http_raw = raw("http")

    src_ip, src_scope = validate_ip(src_raw)
    result_norm, result_http = map_result(result_raw)
    http_status = None
    http_method = None
    if http_raw:
        text = str(http_raw).strip()
        if re.fullmatch(r"\d{3}", text):
            http_status = int(text)
        elif re.fullmatch(r"[A-Z]+", text.upper()) and len(text) <= 7:
            http_method = text.upper()
    if result_http and http_status is None:
        http_status = result_http

    extracted_all: Dict[str, Any] = {}
    for text in (msg_raw, cmd_raw, dst_raw):
        for k, v in extract_from_text(text).items():
            extracted_all.setdefault(k, v)

    # Logon type desde columna o desde el texto.
    logon_type = raw("logon_type") or extracted_all.get("logon_type")

    share = raw("share") or (extracted_all.get("unc_paths", [None])[0] if extracted_all.get("unc_paths") else None)
    file_path = raw("file_path")

    # http/url desde destino si parece URL.
    dst_split = split_destination(dst_raw)
    url_path = None
    web_host = None
    urls = extracted_all.get("urls") or []
    if urls:
        url_m = urls[0]
        web_host, url_path = parse_url(url_m)
        if web_host and not dst_split.get("destination_host"):
            dst_split["destination_host"] = web_host
        if url_path:
            dst_split["url_path"] = url_path

    event: Dict[str, Any] = {
        "log_id": raw("log_id") if log_id_column is not None else None,
        "row_number": row_number,
        "sheet_name": sheet_name,
        "timestamp_raw": str(ts_raw) if ts_raw is not None else None,
        "timestamp_parsed": ts_iso,
        "timestamp_status": ts_status,
        "host_raw": str(host_raw) if host_raw not in (None, "") else None,
        "host_key": normalize_key(host_raw) if host_raw not in (None, "") else None,
        "user_raw": str(user_raw) if user_raw not in (None, "") else None,
        "user_key": normalize_key(user_raw) if user_raw not in (None, "") else None,
        "event_code": str(event_code) if event_code is not None else None,
        "event_description": str(msg_raw) if msg_raw is not None else None,
        "source_ip": src_ip,
        "source_ip_scope": src_scope,
        "destination_raw": dst_split.get("destination_raw"),
        "destination_host": dst_split.get("destination_host"),
        "destination_ip": dst_split.get("destination_ip"),
        "destination_port": dst_split.get("destination_port"),
        "log_source": str(raw("log_source")) if raw("log_source") is not None else None,
        "process_command_line": str(cmd_raw) if cmd_raw is not None else None,
        "process_name": first_token(cmd_raw),
        "parent_process": None,
        "result_raw": str(result_raw) if result_raw is not None else None,
        "result_norm": result_norm,
        "severity_siem": str(raw("sev_siem")) if raw("sev_siem") is not None else None,
        "logon_type": str(logon_type) if logon_type is not None else None,
        "http_method": http_method,
        "http_status": http_status,
        "url_path": url_path or dst_split.get("url_path"),
        "share": str(share) if share is not None else None,
        "file_path": str(file_path) if file_path is not None else None,
        "bytes_out": None,
        "task_name": None,
        "service_name": None,
        "extracted": extracted_all,
        "raw": {
            "fields": row,  # valores crudos conforme al orden detectado de columnas
        },
        "quality_flags": [],
    }

    # status extra: naive/offset ya en timestamp_status; invalid va con flag.
    if ts_status == "invalid":
        event["quality_flags"].append("timestamp_invalid")
    if src_scope == "invalid":
        event["quality_flags"].append("source_ip_invalid")
    return event


def parse_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    m = re.match(r"^(?:https?|ftp)://([^/\s:]+)(?::\d+)?(/[^\s]*)$", url)
    if not m:
        return None, None
    return m.group(1), (m.group(2) or None)


def first_token(cmd: Any) -> Optional[str]:
    """Nombre de proceso desde la linea de comando (heuristica generica)."""
    if cmd is None:
        return None
    text = str(cmd).strip()
    if not text:
        return None
    quoted = re.match(r"^\"([^\"]+)\"", text)
    token = quoted.group(1) if quoted else text.split()[0]
    name = re.split(r"[\\|/]", token)[-1]
    return re.sub(r"\.(exe|dll|ps1|bat|cmd|vbs|py|jar|pl|msi)$", "", name.lower())
