# detection/impl/auth.py - Reglas AUTH-001..005 y AUTH-007 (PLAN seccion 6.2 y 6.3).
# Politicas:
# - El motor ejecuta AUTH-002 ANTES que AUTH-001/AUTH-004: los fallos de fuerza bruta de
#   las victimas de un spraying se absorben en AUTH-002 (absorbed_detail); el exito de la
#   victima correspondiente (AUTH-003) no se absorbe nunca.
# - La agrupacion usa claves canonicas (user_key/host_key); los valores crudos quedan intactos.
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from app.detection.context import Context, is_logon_event
from app.detection.findings import new_finding

StateTuple = Tuple[List[Dict[str, Any]], str, Optional[str]]


def _in_list(value: Optional[str], accepted: List[str]) -> bool:
    return value is not None and str(value).casefold() in {v.casefold() for v in accepted}


def _codes(ev: Dict[str, Any], p: Dict[str, Any], key: str) -> bool:
    return str(ev.get("event_code") or "") in {str(c) for c in p.get(key) or []}


def _is_failure(ev: Dict[str, Any], p: Dict[str, Any]) -> bool:
    return _in_list(ev.get("result_norm"), p.get("failure_results") or []) or _codes(ev, p, "failure_codes")


def _is_success(ev: Dict[str, Any], p: Dict[str, Any]) -> bool:
    return _in_list(ev.get("result_norm"), p.get("success_results") or []) or _codes(ev, p, "success_codes")


def _failures(ctx: Context, p: Dict[str, Any], words: List[str]) -> List[Tuple[Any, Dict[str, Any]]]:
    return ctx.matching(lambda ev: is_logon_event(ev, words) and _is_failure(ev, p))


def _successes(ctx: Context, p: Dict[str, Any], words: List[str]) -> List[Tuple[Any, Dict[str, Any]]]:
    return ctx.matching(lambda ev: is_logon_event(ev, words) and _is_success(ev, p))


def _pair_key(ev: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    user = ev.get("user_key") or ev.get("user_raw")
    ip = ev.get("source_ip")
    if not user or not ip:
        return None
    return (str(user).casefold(), str(ip))


def _user_key(ev: Dict[str, Any]) -> Optional[str]:
    return (ev.get("user_key") or ev.get("user_raw")) or None


def _host_key(ev: Dict[str, Any]) -> str:
    return str(ev.get("host_key") or ev.get("host_raw") or "")


def _is_public(ev: Dict[str, Any]) -> bool:
    return ev.get("source_ip_scope") == "public"


def _wins_with_range(
    items: List[Tuple[Any, Dict[str, Any]]], span_min: int
) -> List[Tuple[Any, Any, List[Tuple[Any, Dict[str, Any]]]]]:
    """Ventanas consecutivas (hueco maximo span_min desde el inicio) con (inicio, fin, items)."""
    out: List[Tuple[Any, Any, List[Tuple[Any, Dict[str, Any]]]]] = []
    if not items:
        return out
    span = timedelta(minutes=span_min)
    window = [items[0]]
    for item in items[1:]:
        if item[0] - window[0][0] <= span:
            window.append(item)
        else:
            out.append((window[0][0], window[-1][0], window))
            window = [item]
    out.append((window[0][0], window[-1][0], window))
    return out


# --------------------------- AUTH-002 (password spraying) ---------------------------

def spray_clusters(ctx: Context, p: Dict[str, Any], words: List[str]) -> List[Dict[str, Any]]:
    """Clusters de spray: misma IP, >= min_users victimas, <= max_attempts_per_user fallos por
    victima, dentro de una ventana de window_minutes. Solo devuelve ventanas que califican."""
    failures = _failures(ctx, p, words)
    by_ip: Dict[str, List[Tuple[Any, Dict[str, Any]]]] = {}
    for dt, ev in failures:
        ip = ev.get("source_ip")
        if ip:
            by_ip.setdefault(str(ip), []).append((dt, ev))
    clusters: List[Dict[str, Any]] = []
    for ip, items in by_ip.items():
        items.sort(key=lambda x: (x[0], str(x[1].get("log_id"))))
        for wstart, wend, window in _wins_with_range(items, int(p.get("window_minutes", 60))):
            events = [ev for _, ev in window if _pair_key(ev)]
            if not events:
                continue
            users: Dict[str, int] = {}
            for ev in events:
                k = _pair_key(ev)[0]
                users[k] = users.get(k, 0) + 1
            cl_scope = events[0].get("source_ip_scope")
            if len(users) < int(p.get("min_users", 5)):
                continue
            if max(users.values()) > int(p.get("max_attempts_per_user", 6)):
                continue
            # Anti-ruido: un cluster interno (no publico) necesita volumen minimo;
            # un origen publico con muchas cuentas victimas califica por si solo.
            if cl_scope != "public" and len(events) < int(p.get("min_total_attempts", 0)):
                continue
            clusters.append(
                {
                    "ip": ip,
                    "events": events,
                    "users": users,
                    "start": wstart,
                    "end": wend,
                    "ip_scope": events[0].get("source_ip_scope"),
                }
            )
    return clusters


def auth_002(ctx: Context, rule, state) -> StateTuple:
    p = rule.parameters or {}
    clusters = spray_clusters(ctx, p, p.get("logon_event_words") or [])
    absorbed: Dict[str, Dict[str, Any]] = {}
    for cl in clusters:
        for ev in cl["events"]:
            absorbed[str(ev.get("log_id"))] = cl
    state["spray_absorbed"] = absorbed
    findings = []
    for cl in clusters:
        hechos = [
            f"La IP origen {cl['ip']} acumuló {len(cl['events'])} fallos de autenticación contra "
            f"{len(cl['users'])} usuarios distintos entre {cl['start'].isoformat()} y {cl['end'].isoformat()}.",
            f"Máximo de intentos fallidos por usuario: {max(cl['users'].values())} "
            f"(umbral de spraying: ≤ {p.get('max_attempts_per_user')}).",
        ]
        inferencia = [
            "Pocas tentativas por cuenta sobre muchas identidades desde un mismo origen es compatible "
            "con un barrido de contraseñas; el propio patrón no prueba qué intento consiguió acceso."
        ]
        findings.append(
            new_finding(
                cursor=state["cursor"],
                rule=rule,
                events=cl["events"],
                hecho=hechos,
                inferencia=inferencia,
                factors=["origen_publico"] if cl.get("ip_scope") == "public" else [],
                absorbed_detail={"auth_001_absorvidas": {"ip": cl["ip"], "victimas": sorted(cl["users"].keys())}},
            )
        )
    if findings:
        return findings, "executed", None
    return [], "executed_no_findings", None


# --------------------------- AUTH-001 (fuerza bruta por usuario/IP) ---------------------------

def auth_001(ctx: Context, rule, state) -> StateTuple:
    p = rule.parameters or {}
    spray_absorbed = state.get("spray_absorbed") or {}
    by_pair: Dict[Tuple[str, str], List[Tuple[Any, Dict[str, Any]]]] = {}
    for dt, ev in _failures(ctx, p, p.get("logon_event_words") or []):
        if str(ev.get("log_id")) in spray_absorbed:
            continue  # absorbidas por el spraying del mismo origen (AUTH-002)
        k = _pair_key(ev)
        if k:
            by_pair.setdefault(k, []).append((dt, ev))
    findings = []
    for (user, ip), items in by_pair.items():
        items.sort(key=lambda x: (x[0], str(x[1].get("log_id"))))
        for wstart, wend, window in _wins_with_range(items, int(p.get("window_minutes", 15))):
            events = [ev for _, ev in window]
            if len(events) < int(p.get("min_failures", 5)):
                continue
            hechos = [
                f"{len(events)} fallos de autenticación del usuario {events[0].get('user_raw')} "
                f"desde {ip} entre {wstart.isoformat()} y {wend.isoformat()}."
            ]
            findings.append(new_finding(cursor=state["cursor"], rule=rule, events=events, hecho=hechos))
    if findings:
        return findings, "executed", None
    return [], "executed_no_findings", None


# --------------------------- AUTH-003 (exito tras fallos) ---------------------------

def auth_003(ctx: Context, rule, state) -> StateTuple:
    p = rule.parameters or {}
    words = p.get("logon_event_words") or []
    mins = timedelta(minutes=int(p.get("window_minutes", 25)))
    need = int(p.get("min_failures", 3))
    failures = _failures(ctx, p, words)
    findings = []
    reported: set = set()
    for sdt, sev in _successes(ctx, p, words):
        suser = _user_key(sev)
        if not suser:
            continue
        prior = [
            (fdt, fev)
            for fdt, fev in failures
            if 0 <= (sdt - fdt).total_seconds() <= mins.total_seconds()
            and _user_key(fev) == suser
            and (fev.get("source_ip") == sev.get("source_ip") or sev.get("source_ip") is None)
        ]
        if len(prior) < need:
            continue
        key = (suser, str(sev.get("log_id")))
        if key in reported:
            continue
        reported.add(key)
        ips_prev = sorted({str(fev.get("source_ip")) for _, fev in prior if fev.get("source_ip")})
        hechos = [
            f"Autenticación exitosa ({sev.get('event_code') or 'código no declarado'}) del usuario "
            f"{sev.get('user_raw')} sobre {sev.get('host_raw') or 'host no declarado'} a las {sdt.isoformat()}.",
            f"Precedida por {len(prior)} fallos de la misma identidad en la ventana de {p.get('window_minutes')} min "
            f"con origen(es) {' / '.join(ips_prev) if ips_prev else 'no declarado'}.",
        ]
        factors = ["origen_publico"] if _is_public(sev) else []
        findings.append(
            new_finding(
                cursor=state["cursor"],
                rule=rule,
                events=[sev] + [ev for _, ev in prior],
                hecho=hechos,
                inferencia=[
                    "Un éxito tras fallos repetidos de la misma identidad es consistente con que la fuerza "
                    "bruta o el spray consiguió acceso; conviene revisar y resetear la cuenta afectada.",
                ],
                factors=factors,
            )
        )
    if findings:
        return findings, "executed", None
    return [], "executed_no_findings", None


# --------------------------- AUTH-004 (login desde IP publica) ---------------------------

def auth_004(ctx: Context, rule, state) -> StateTuple:
    p = rule.parameters or {}
    words = p.get("logon_event_words") or []
    spray_absorbed = state.get("spray_absorbed") or {}
    findings = []
    for sdt, sev in _successes(ctx, p, words):
        sip = sev.get("source_ip")
        if not sip or not _is_public(sev):
            continue
        hechos = [
            f"Autenticación exitosa ({sev.get('event_code') or 'código no declarado'}) desde IP pública {sip} "
            f"hacia el activo interno {sev.get('host_raw') or 'host no declarado'} a las {sdt.isoformat()}."
        ]
        findings.append(
            new_finding(
                cursor=state["cursor"],
                rule=rule,
                events=[sev],
                hecho=hechos,
                inferencia=[
                    "Un acceso válido externo sobre activo interno puede indicar credenciales comprometidas o exposición indebida del servicio.",
                ],
                factors=["origen_publico"],
            )
        )
    # Fallos desde IP publica que no esten absorbidos por el spray de la misma IP.
    by_host: Dict[Tuple[str, str], List[Tuple[Any, Dict[str, Any]]]] = {}
    for dt, ev in _failures(ctx, p, words):
        sip = ev.get("source_ip")
        if not sip or not _is_public(ev) or str(ev.get("log_id")) in spray_absorbed:
            continue
        k = (str(sip), _host_key(ev))
        by_host.setdefault(k, []).append((dt, ev))
    for (sip, host), items in by_host.items():
        events = [ev for _, ev in items]
        hechos = [
            f"{len(events)} fallos de autenticación desde IP pública {sip} hacia el activo interno "
            f"{host or 'host no declarado'} entre {items[0][0].isoformat()} y {items[-1][0].isoformat()}."
        ]
        findings.append(
            new_finding(
                cursor=state["cursor"],
                rule=rule,
                events=events,
                hecho=hechos,
                inferencia=[
                    "Fallos externos sobre activo interno indican intentos por credenciales o un servicio de acceso expuesto.",
                ],
                factors=["origen_publico"],
            )
        )
    if findings:
        return findings, "executed", None
    return [], "executed_no_findings", None


# --------------------------- AUTH-005 (RDP sospechoso) ---------------------------

def auth_005(ctx: Context, rule, state) -> StateTuple:
    p = rule.parameters or {}
    rdp_type = str(p.get("rdp_type", "10"))
    words = p.get("logon_event_words") or []
    events = [
        ev
        for _, ev in ctx.matching(
            lambda ev: str(ev.get("logon_type") or "") == rdp_type and is_logon_event(ev, words)
        )
    ]
    if not events:
        return [], "executed_no_findings", None
    by_host: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        by_host.setdefault(_host_key(ev), []).append(ev)
    findings = []
    for evs in by_host.values():
        evs.sort(key=lambda e: (e["_ts"], str(e.get("log_id"))))
        bbox = [(e["_ts"], e) for e in evs]
        for wstart, wend, window in _wins_with_range(bbox, int(p.get("window_minutes", 30))):
            groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
            for _, ev in window:
                k = (str(_user_key(ev) or ""), str(ev.get("source_ip") or ""))
                groups.setdefault(k, []).append(ev)
            for (user, sip), evs2 in groups.items():
                fails = [
                    e
                    for e in evs2
                    if e.get("result_norm") in ("failure", "denied") or str(e.get("event_code")) == "4625"
                ]
                if len(fails) < int(p.get("fail_threshold", 2)):
                    continue
                hechos = [
                    f"{len(fails)} fallos de sesión RDP (LogonType {rdp_type}) del usuario "
                    f"{evs2[-1].get('user_raw')} sobre {evs2[-1].get('host_raw') or 'host no declarado'} "
                    f"con origen {sip or 'no declarado'} entre {wstart.isoformat()} y {wend.isoformat()}."
                ]
                if any(e.get("result_norm") == "success" for e in evs2):
                    hechos.append("También existe una autenticación RDP exitosa del mismo usuario/origen en la ventana.")
                findings.append(
                    new_finding(
                        cursor=state["cursor"],
                        rule=rule,
                        events=evs2,
                        hecho=hechos,
                        factors=["origen_publico"] if _is_public(evs2[-1]) else [],
                    )
                )
    if findings:
        return findings, "executed", None
    return [], "executed_no_findings", None


# --------------------------- AUTH-007 (cuenta de servicio interactiva) ---------------------------

def auth_007(ctx: Context, rule, state) -> StateTuple:
    p = rule.parameters or {}
    patterns = [str(x).casefold() for x in p.get("user_patterns") or []]
    if not patterns:
        return [], "executed_no_findings", "sin patrones de cuenta configurados"
    span_min = int(p.get("window_minutes", 30))
    window = timedelta(minutes=span_min)
    inter_codes = {str(c) for c in p.get("interactive_codes") or []}
    pers_codes = {str(c) for c in p.get("extra_codes_persistence") or []}

    def is_svc(ev: Dict[str, Any]) -> bool:
        user = str(ev.get("user_raw") or "").casefold()
        return bool(user) and any(tok in user for tok in patterns)

    svc_inter = ctx.matching(lambda ev: is_svc(ev) and str(ev.get("event_code")) in inter_codes)
    if not svc_inter:
        return [], "executed_no_findings", None
    by_user_host: Dict[Tuple[str, str], List[Tuple[Any, Dict[str, Any]]]] = {}
    for dt, ev in svc_inter:
        by_user_host.setdefault((str(_user_key(ev) or ""), _host_key(ev)), []).append((dt, ev))
    findings = []
    for (user, host), items in by_user_host.items():
        items.sort(key=lambda x: (x[0], str(x[1].get("log_id"))))
        for wstart, wend, witems in _wins_with_range(items, span_min):
            rel = [
                (edt, eev)
                for edt, eev in ctx.matching(is_svc)
                if _user_key(eev) == user
                and (wstart - window) <= edt <= (wend + window)
                and (
                    # La senal adicional debe ser del mismo host (persistencia) o de
                    # origen publico con exito/privilegios (no meros fallos del usuario).
                    (
                        eev.get("source_ip_scope") == "public"
                        and (
                            _is_success(eev, {"success_results": ["success"], "success_codes": []})
                            or str(eev.get("event_code")) == "4672"
                        )
                    )
                    or (_host_key(eev) == host and str(eev.get("event_code")) in pers_codes)
                )
            ]
            if not rel:
                continue
            events = [ev for _, ev in witems]
            hechos = [
                f"Actividad interactiva (código {events[0].get('event_code')}) de la cuenta con patrón de "
                f"servicio {events[0].get('user_raw')} sobre {host or 'host no declarado'} entre "
                f"{wstart.isoformat()} y {wend.isoformat()}."
            ]
            public_ids = sorted(str(e.get("log_id")) for _, e in rel if e.get("source_ip_scope") == "public")
            pers_ids = sorted(str(e.get("log_id")) for _, e in rel if str(e.get("event_code")) in pers_codes)
            if public_ids:
                hechos.append(f"Origen público de la misma cuenta vinculado en la ventana: Log_ID {', '.join(public_ids)}.")
            if pers_ids:
                hechos.append(f"Persistencia cercana de la misma cuenta: Log_ID {', '.join(pers_ids)}.")
            findings.append(
                new_finding(
                    cursor=state["cursor"],
                    rule=rule,
                    events=events + [e for _, e in rel],
                    hecho=hechos,
                    inferencia=[
                        "Las cuentas de servicio normalmente no inician sesión interactiva; la coincidencia "
                        "con otra señal sugiere uso indebido de la cuenta.",
                    ],
                )
            )
    if findings:
        return findings, "executed", None
    return [], "executed_no_findings", None


RULES = {
    "AUTH-001": auth_001,
    "AUTH-002": auth_002,
    "AUTH-003": auth_003,
    "AUTH-004": auth_004,
    "AUTH-005": auth_005,
    "AUTH-007": auth_007,
}
