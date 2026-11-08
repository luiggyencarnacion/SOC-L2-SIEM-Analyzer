# detection/impl/lateral.py - Reglas LAT-001..004.
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from app.detection.context import concat_text, first_unc, is_logon_event
from app.detection.findings import clip_text, list_fmt, new_finding
from app.detection.impl.auth import _host_key, _is_public, _is_success, _user_key

StateTuple = Tuple[List[Dict[str, Any]], str, Optional[str]]


def _code(ev: Dict[str, Any]) -> str:
    return str(ev.get("event_code") or "")


def _anchors(ctx, words: List[str], success_results: List[str]) -> List[Tuple[Any, Dict[str, Any]]]:
    """Anclas LAT-001/003: logon exitoso con origen publico."""
    out = []
    for dt, ev in ctx.matching(
        lambda ev: is_logon_event(ev, words)
        and _is_success(ev, {"success_results": success_results, "success_codes": []})
    ):
        if _is_public(ev) and ev.get("user_key"):
            out.append((dt, ev))
    return sorted(out, key=lambda x: (x[0], str(x[1].get("log_id"))))


# --------------------------- LAT-001 ---------------------------

def lat_001(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    window = timedelta(minutes=int(p.get("window_minutes", 30)))
    words = p.get("logon_event_words") or []
    lat_types = {str(t) for t in p.get("lateral_types") or []}
    share_codes = {str(c) for c in p.get("lateral_codes_shares") or []}
    success_results = p.get("success_results") or ["success"]

    findings = []
    used_data_keys: set = set()
    for adt, aev in _anchors(ctx, words, success_results):
        user = str(_user_key(aev))
        anchor_host = _host_key(aev)

        def lateral_candidate(ev: Dict[str, Any], usr=user, anc=adt) -> bool:
            if _user_key(ev) != usr:
                return False
            host = _host_key(ev)
            if not host or host == str(aev.get("host_key") or anchor_host):
                return False
            is_type3 = str(ev.get("logon_type") or "") in lat_types
            is_share = _code(ev) in share_codes or bool(first_unc(ev))
            has_source_text = bool((ev.get("extracted") or {}).get("origen_en_texto"))
            return is_type3 or is_share or has_source_text

        lat_events = [
            eev for edt, eev in ctx.matching(lateral_candidate) if adt <= edt <= adt + window
        ]
        if not lat_events:
            continue
        data_key = (user, tuple(sorted({_host_key(e) for e in lat_events})), anchor_host)
        if data_key in used_data_keys:
            continue
        used_data_keys.add(data_key)
        hosts = sorted({e.get("host_raw") or "host no declarado" for e in lat_events})
        hechos = [
            f"Tras un logon exitoso externo de {aev.get('user_raw')} desde {aev.get('source_ip')} a las "
            f"{adt.isoformat()} (host {aev.get('host_raw') or 'host no declarado'}), la misma identidad aparece "
            f"activa en {list_fmt(hosts, 3)} dentro de {p.get('window_minutes')} min "
            f"({len(lat_events)} evento(s) lateral(es))."
        ]
        source_logs = sorted(
            str(e.get("log_id")) for e in lat_events if (e.get("extracted") or {}).get("origen_en_texto")
        )
        if source_logs:
            hechos.append(f"Eventos con origen declarado en el texto (source=<host>): inicio {', '.join(source_logs[:4])}.")
        findings.append(
            new_finding(
                cursor=state["cursor"],
                rule=rule,
                events=[aev] + lat_events,
                hecho=hechos,
                inferencia=[
                    "La reaparición de la identidad externa en otro host con LogonType 3, share o source=<host> "
                    "es consistente con movimiento lateral; se mantiene la identidad cruda en cada evidencia.",
                ],
                factors=["origen_publico"],
            )
        )
    return (findings, "executed", None) if findings else ([], "executed_no_findings", None)


# --------------------------- LAT-002 ---------------------------

def lat_002(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    sensitive = [s.casefold() for s in p.get("sensitive_tokens") or []]
    share_codes = {str(c) for c in p.get("share_codes") or []}
    max_single = int(p.get("max_single_accesses", 3))
    window = timedelta(minutes=int(p.get("window_minutes", 30)))

    def is_sensitive_share_event(ev: Dict[str, Any]) -> bool:
        if _code(ev) not in share_codes:
            return False
        text = concat_text(ev, ["share", "destination_raw", "event_description", "file_path"]).casefold()
        return any(tok in text for tok in sensitive)

    events = ctx.matching(is_sensitive_share_event)
    if not events:
        return [], "executed_no_findings", None
    groups: Dict[Tuple, List[Tuple[Any, Dict[str, Any]]]] = {}
    for dt, ev in events:
        k = (str(_user_key(ev) or ""), _host_key(ev))
        groups.setdefault(k, []).append((dt, ev))
    findings = []
    for (user, host), items in groups.items():
        items.sort(key=lambda x: (x[0], str(x[1].get("log_id"))))
        cur = [items[0]]
        windows: List[List[Tuple[Any, Dict[str, Any]]]] = []
        for item in items[1:]:
            if item[0] - cur[-1][0] <= window:
                cur.append(item)
            else:
                windows.append(cur)
                cur = [item]
        windows.append(cur)
        for w in windows:
            if len(w) > max_single:
                continue  # el torrente masivo lo cubre EXF-004; LAT-002 solo accesos esporadicos
            evs = [ev for _, ev in w]
            shares = sorted({first_unc(e) or (e.get("destination_raw") or "share no declarado") for e in evs})
            hechos = [
                f"Acceso esporádico ({len(evs)} evento(s)) a shares sensibles por {evs[0].get('user_raw')} "
                f"en {evs[0].get('host_raw') or 'host no declarado'} entre {w[0][0].isoformat()} y "
                f"{w[-1][0].isoformat()}: {list_fmt(shares, 3)}."
            ]
            findings.append(
                new_finding(
                    cursor=state["cursor"],
                    rule=rule,
                    events=evs,
                    hecho=hechos,
                    factors=["acceso_a_datos_sensibles"],
                    inferencia=["El acceso puntual a datos sensibles suele preceder a la recolección o exfiltración de la información."],
                )
            )
    return (findings, "executed", None) if findings else ([], "executed_no_findings", None)


# --------------------------- LAT-003 ---------------------------

def lat_003(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    lat_types = {str(t) for t in p.get("lateral_types") or []}
    min_hops = int(p.get("min_hops", 2))
    window = timedelta(minutes=int(p.get("window_minutes_after_anchor", 30)))
    success_results = p.get("success_results") or ["success"]

    def type3_success(ev: Dict[str, Any], usr: str) -> bool:
        if _user_key(ev) != usr:
            return False
        if str(ev.get("logon_type") or "") not in lat_types:
            return False
        return _is_success(ev, {"success_results": success_results, "success_codes": []})

    findings = []
    for adt, aev in _anchors(ctx, p.get("logon_event_words") or [], success_results):
        user = str(_user_key(aev))
        anchor_host = str(aev.get("host_key") or anchor_host_key(aev))
        hops = [
            (edt, eev)
            for edt, eev in ctx.matching(lambda ev: type3_success(ev, user))
            if adt < edt <= adt + window and _host_key(eev) and _host_key(eev) != anchor_host
        ]
        hosts_seq: List[str] = []
        for edt, eev in sorted(hops, key=lambda x: x[0]):
            h = _host_key(eev)
            if not hosts_seq or hosts_seq[-1] != h:
                hosts_seq.append(h)
        if len(hops) < min_hops or len(hosts_seq) < min_hops:
            continue
        hechos = [
            f"El usuario {aev.get('user_raw')} acumuló {len(hops)} logons de red exitosos (LogonType "
            f"{'/'.join(sorted(lat_types))}) en la cadena de hosts {', '.join(hosts_seq)} tras el ancla externa "
            f"del host {aev.get('host_raw') or 'no declarado'} a las {adt.isoformat()}."
        ]
        findings.append(
            new_finding(
                cursor=state["cursor"],
                rule=rule,
                events=[aev] + [e for _, e in hops],
                hecho=hechos,
                inferencia=["Con dos o más saltos la identidad se desplaza explícitamente por la red entre activos."],
                factors=["origen_publico"],
            )
        )
    return (findings, "executed", None) if findings else ([], "executed_no_findings", None)


def anchor_host_key(ev: Dict[str, Any]) -> str:
    return _host_key(ev)


# --------------------------- LAT-004 ---------------------------

def lat_004(ctx, rule, state) -> StateTuple:
    # Requiere línea base histórica de destinos por host; no se puede derivar de un export
    # puntual sin datos previos. Cobertura: datos insuficientes.
    return [], "insufficient_data", (
        "requiere una línea base histórica de destinos por host que no se puede derivar del "
        "archivo exportado con los datos actuales."
    )


RULES = {"LAT-001": lat_001, "LAT-002": lat_002, "LAT-003": lat_003, "LAT-004": lat_004}
