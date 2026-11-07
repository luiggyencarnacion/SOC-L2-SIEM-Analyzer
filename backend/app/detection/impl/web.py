# detection/impl/web.py - Reglas WEB-001..003.
from typing import Any, Dict, List, Optional, Tuple

from app.detection.context import concat_text
from app.detection.findings import clip_text, new_finding
from app.detection.impl.auth import _host_key, _user_key

StateTuple = Tuple[List[Dict[str, Any]], str, Optional[str]]


def _code(ev: Dict[str, Any]) -> str:
    return str(ev.get("event_code") or "")


def web_url_text(ev: Dict[str, Any]) -> str:
    """Texto 'URL' del evento: url_path, o desde cmd/destino (la URL puede venir en la
    columna de comando o en el destino segun el formato del export)."""
    for field in ("url_path", "process_command_line", "destination_raw", "event_description"):
        val = ev.get(field)
        if val and ("/" in str(val) or "?" in str(val)):
            return str(val).casefold()
    return ""


def _is_web_event(ev: Dict[str, Any]) -> bool:
    return (
        ev.get("http_status") is not None
        or bool(web_url_text(ev))
        or str(ev.get("log_source") or "").casefold() == "iis"
    )


# --------------------------- WEB-001 ---------------------------

def web_001(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    errors = {int(s) for s in p.get("error_statuses") or []}
    min_errors = int(p.get("min_errors", 10))
    from datetime import timedelta

    window = timedelta(minutes=int(p.get("window_minutes", 15)))

    def pred(ev):
        if not _is_web_event(ev):
            return False
        status = ev.get("http_status")
        return isinstance(status, int) and status in errors

    groups: Dict[Tuple, List[Tuple[Any, Dict[str, Any]]]] = {}
    for dt, ev in ctx.matching(pred):
        k = (str(ev.get("source_ip") or "sin origen"), _host_key(ev))
        groups.setdefault(k, []).append((dt, ev))
    findings = []
    for (src, host), items in groups.items():
        items.sort(key=lambda x: (x[0], str(x[1].get("log_id"))))
        cur = [items[0]]
        windows: List[List[Tuple[Any, Dict[str, Any]]]] = []
        for item in items[1:]:
            if item[0] - cur[0][0] <= window:
                cur.append(item)
            else:
                windows.append(cur)
                cur = [item]
        windows.append(cur)
        for w in windows:
            if len(w) < min_errors:
                continue
            evs = [ev for _, ev in w]
            hechos = [
                f"{len(evs)} respuestas {'/'.join(str(s) for s in p.get('error_statuses') or [])} desde {src} hacia "
                f"{evs[0].get('host_raw') or 'host web no declarado'} en menos de "
                f"{p.get('window_minutes')} min ({w[0][0].isoformat()} → {w[-1][0].isoformat()})."
            ]
            hechos.append(f"Rutas afectadas: {'; '.join(web_url_text(e) or '-' for e in evs[:3])}.")
            findings.append(
                new_finding(
                    cursor=state["cursor"], rule=rule, events=evs, hecho=hechos,
                    inferencia=["Bombardear la aplicación con respuestas de error consecutivas suele delatar escaneo de rutas o fuerza de credenciales automatizada."],
                )
            )
    return (findings, "executed", None) if findings else ([], "executed_no_findings", None)


# --------------------------- WEB-002 ---------------------------

def web_002(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    tokens = [s.casefold() for s in p.get("path_tokens") or []]
    min_req = int(p.get("min_requests", 5))
    from datetime import timedelta

    window = timedelta(minutes=int(p.get("window_minutes", 30)))

    def pred(ev):
        if not _is_web_event(ev):
            return False
        url = web_url_text(ev)
        return bool(url) and any(tok in url for tok in tokens)

    groups: Dict[Tuple, List[Tuple[Any, Dict[str, Any]]]] = {}
    for dt, ev in ctx.matching(pred):
        k = (str(ev.get("source_ip") or "sin origen"), _host_key(ev))
        groups.setdefault(k, []).append((dt, ev))
    findings = []
    for (src, host), items in groups.items():
        items.sort(key=lambda x: (x[0], str(x[1].get("log_id"))))
        cur = [items[0]]
        windows: List[List[Tuple[Any, Dict[str, Any]]]] = []
        for item in items[1:]:
            if item[0] - cur[0][0] <= window:
                cur.append(item)
            else:
                windows.append(cur)
                cur = [item]
        windows.append(cur)
        for w in windows:
            if len(w) < min_req:
                continue
            evs = [ev for _, ev in w]
            hechos = [
                f"{len(evs)} peticiones a rutas de administración/login con usuarios en la URL desde {src} hacia "
                f"{evs[0].get('host_raw') or 'host web no declarado'} "
                f"({w[0][0].isoformat()} → {w[-1][0].isoformat()})."
            ]
            hechos.append(f"URLs: {'; '.join(web_url_text(e) or '-' for e in evs[:3])}.")
            findings.append(
                new_finding(
                    cursor=state["cursor"], rule=rule, events=evs, hecho=hechos,
                    inferencia=["El bombardeo repetido a rutas de login/admin delata intento de descubrir credenciales o cuentas válidas."],
                )
            )
    return (findings, "executed", None) if findings else ([], "executed_no_findings", None)


# --------------------------- WEB-003 ---------------------------

def web_003(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    cmd_params = [s.casefold() for s in p.get("cmd_param_names") or []]
    shell_tokens = [s.casefold() for s in p.get("shell_tokens") or []]
    pool_tokens = [s.casefold() for s in p.get("app_pool_tokens") or []]
    from datetime import timedelta

    window = timedelta(minutes=int(p.get("window_minutes", 15)))

    def url_shell_hits(ev: Dict[str, Any]) -> bool:
        url = web_url_text(ev)
        if not url:
            return False
        for cp in cmd_params:
            idx = url.find(cp)
            if idx < 0:
                continue
            needle = (url[idx + len(cp):].split('&')[0] or "")
            if any(tok in needle for tok in shell_tokens):
                return True
        return False

    def pool_shell_hits(ev: Dict[str, Any]) -> bool:
        user = str(ev.get("user_raw") or "").casefold()
        if not any(tok in user for tok in pool_tokens):
            return False
        text = concat_text(ev, ["process_command_line", "event_description"]).casefold()
        return any(tok in text for tok in shell_tokens)

    url_hits = [(dt, ev) for dt, ev in ctx.matching(url_shell_hits)]
    pool_hits = [(dt, ev) for dt, ev in ctx.matching(lambda ev: _code(ev) == "4688" and pool_shell_hits(ev))]
    if not url_hits and not pool_hits:
        return [], "executed_no_findings", None

    # Agrupa por host en ventanas para no fragmentar el matches: un webshell completo.
    groups: Dict[str, List[Tuple[Any, Dict[str, Any]]]] = {}
    for dt, ev in url_hits + pool_hits:
        k = _host_key(ev)
        groups.setdefault(k, []).append((dt, ev))
    findings = []
    for host, items in groups.items():
        items.sort(key=lambda x: (x[0], str(x[1].get("log_id"))))
        cur = [items[0]]
        windows: List[List[Tuple[Any, Dict[str, Any]]]] = []
        for item in items[1:]:
            if item[0] - cur[0][0] <= window:
                cur.append(item)
            else:
                windows.append(cur)
                cur = [item]
        windows.append(cur)
        for w in windows:
            evs = [ev for _, ev in w]
            urls = [str(e.get("url_path")) for e in evs if e.get("url_path")]
            procs = sorted({str(e.get("process_name") or "") for e in evs if e.get("process_name")})
            hechos = []
            if urls:
                hechos.append(
                    f"Inyección de comandos en URL contra {evs[0].get('host_raw') or host}: "
                    f"{len(urls)} peticiones con shell ({'; '.join(urls[:3])}) desde {evs[0].get('source_ip') or 'origen no declarado'}."
                )
            if procs:
                hechos.append(
                    f"Proceso hijo de shell bajo identidad del pool de la aplicación ({evs[-1].get('user_raw') or 'no declarada'}): "
                    f"{', '.join(procs)} a las {evs[-1]['_ts'].isoformat()}."
                )
            findings.append(
                new_finding(
                    cursor=state["cursor"], rule=rule, events=evs, hecho=hechos,
                    factors=["explotacion_web"],
                    inferencia=["La combinación de comandos en la weburl y un shell hijo bajo el app pool es evidencia directa de webshell."],
                )
            )
    return (findings, "executed", None) if findings else ([], "executed_no_findings", None)


RULES = {"WEB-001": web_001, "WEB-002": web_002, "WEB-003": web_003}
