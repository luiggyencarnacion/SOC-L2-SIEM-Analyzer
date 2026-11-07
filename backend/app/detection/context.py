# detection/context.py - Indexes del analisis: tiempo, referencias y filtros comunes.
# Deteccion determinista: solo datos ya normalizados por la fase A.
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple


def parse_ts(event: Dict[str, Any]) -> Optional[datetime]:
    iso = event.get("timestamp_parsed")
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso)
    except ValueError:
        return None


class Context:
    """Pasa por reglas: eventos ordenados por tiempo y busquedas por referencia."""

    def __init__(self, events: List[Dict[str, Any]]):
        self.events = events
        self.by_log_id: Dict[str, Dict[str, Any]] = {}
        timed: List[Tuple[datetime, Dict[str, Any]]] = []
        for ev in events:
            lid = str(ev.get("log_id"))
            self.by_log_id[lid] = ev
            dt = parse_ts(ev)
            if dt is None:
                continue
            ev["_ts"] = dt  # cache interno; se limpia con drop_internal()
            timed.append((dt, ev))
        timed.sort(key=lambda pair: (pair[0], str(pair[1].get("log_id"))))
        self.timed: List[Tuple[datetime, Dict[str, Any]]] = timed

    def drop_internal(self) -> None:
        for ev in self.events:
            ev.pop("_ts", None)

    # --------- filtros comunes sobre eventos con timestamp ---------
    def matching(self, pred) -> List[Tuple[datetime, Dict[str, Any]]]:
        return [(dt, ev) for dt, ev in self.timed if pred(ev)]

    def group_by_window(
        self, items: List[Tuple[datetime, Dict[str, Any]]], minutes: int
    ) -> List[List[Tuple[datetime, Dict[str, Any]]]]:
        """Agrupa items consecutivos si el hueco entre el primero y el siguiente <= minutos."""
        if not items:
            return []
        out: List[List[Tuple[datetime, Dict[str, Any]]]] = []
        window: List[Tuple[datetime, Dict[str, Any]]] = [items[0]]
        span = timedelta(minutes=minutes)
        for item in items[1:]:
            if item[0] - window[0][0] <= span:
                window.append(item)
            else:
                out.append(window)
                window = [item]
        out.append(window)
        return out


# ---------------- getters de campos universales ----------------

def field_getter(field: str):
    """Devuelve una funcion event->valor para el campo abreviado del YAML."""
    table = {
        "ts": lambda e: e.get("timestamp_parsed"),
        "host": lambda e: e.get("host_key") or e.get("host_raw"),
        "host_raw": lambda e: e.get("host_raw"),
        "user": lambda e: e.get("user_key") or e.get("user_raw"),
        "user_raw": lambda e: e.get("user_raw"),
        "src_ip": lambda e: e.get("source_ip"),
        "dst": lambda e: e.get("destination_host") or e.get("destination_raw"),
        "event_code": lambda e: e.get("event_code"),
        "msg": lambda e: e.get("event_description"),
        "cmd": lambda e: e.get("process_command_line"),
        "result": lambda e: e.get("result_norm"),
        "log_source": lambda e: e.get("log_source"),
        "sev_siem": lambda e: e.get("severity_siem"),
        "logon_type": lambda e: e.get("logon_type"),
        "http": lambda e: e.get("http_status") or e.get("http_method"),
        "share": lambda e: e.get("share") or first_unc(e),
        "file_path": lambda e: e.get("file_path"),
        "bytes_out": lambda e: e.get("bytes_out"),
        "task_service": lambda e: e.get("task_name") or e.get("service_name"),
    }
    return table.get(field, lambda e: None)


def first_unc(event: Dict[str, Any]) -> Optional[str]:
    ex = event.get("extracted") or {}
    uncs = ex.get("unc_paths")
    if isinstance(uncs, list) and uncs:
        return str(uncs[0])
    return None


def is_logon_event(event: Dict[str, Any], words: List[str]) -> bool:
    """Identifica evento de autenticacion: codigo logon conocido o frase declarada."""
    codes = {"4624", "4625", "4776"}
    code = str(event.get("event_code") or "")
    if code in codes:
        return True
    desc = (event.get("event_description") or "").casefold()
    return any(w.casefold() in desc for w in words)


def concat_text(event: Dict[str, Any], fields: List[str]) -> str:
    """Une datos libre de varios campos para el matching de patrones."""
    parts = []
    for f in fields:
        val = event.get(f)
        if val:
            parts.append(str(val))
    ex = event.get("extracted") or {}
    if ex.get("paths"):
        parts.extend(str(p) for p in ex["paths"])
    return " ".join(parts)
