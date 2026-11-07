# detection/impl/privilege.py - Reglas PRIV-001 y PRIV-002.
from typing import Any, Dict, List, Optional, Tuple

from app.detection.findings import new_finding
from app.detection.impl.auth import _host_key, _user_key

StateTuple = Tuple[List[Dict[str, Any]], str, Optional[str]]


def _code_in(ev: Dict[str, Any], codes: List[str]) -> bool:
    return str(ev.get("event_code") or "") in {str(c) for c in codes}


def priv_001(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    events = [ev for _, ev in ctx.matching(lambda ev: _code_in(ev, p.get("codes") or []))]
    if not events:
        return [], "executed_no_findings", None
    findings = []
    for ev in events:
        hechos = [
            f"Evento {ev.get('event_code')} de cambios en cuentas/grupos privilegiados registrado "
            f"en {ev.get('host_raw') or 'host no declarado'} a las {ev['_ts'].isoformat()} "
            f"con cuenta {ev.get('user_raw') or 'no declarada'}."
        ]
        findings.append(new_finding(cursor=state["cursor"], rule=rule, events=[ev], hecho=hechos))
    return findings, "executed", None


def priv_002(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    scopes = set(p.get("anomalous_scopes") or [])
    events = [
        (dt, ev)
        for dt, ev in ctx.matching(lambda ev: _code_in(ev, p.get("codes") or []))
        if not scopes or ev.get("source_ip_scope") in scopes
    ]
    if not events:
        return [], "executed_no_findings", None
    # Agrupa por (usuario, origen, host) para no inflar hallazgos repetidos.
    groups: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for dt, ev in events:
        k = (str(_user_key(ev) or ""), str(ev.get("source_ip") or ""), _host_key(ev))
        groups.setdefault(k, []).append(ev)
    findings = []
    for (user, sip, host), evs in sorted(groups.items(), key=lambda kv: kv[1][0]["_ts"]):
        hechos = [
            f"Se asignaron privilegios especiales ({', '.join(p.get('codes') or [])}) a {evs[0].get('user_raw')} "
            f"desde {sip} sobre {evs[0].get('host_raw') or 'host no declarado'} "
            f"({len(evs)} evento(s), {evs[0]['_ts'].isoformat()})."
        ]
        hechos.append("Contexto anómalo por configuración: origen con IP pública.")
        findings.append(
            new_finding(
                cursor=state["cursor"],
                rule=rule,
                events=evs,
                hecho=hechos,
                factors=["origen_publico"],
            )
        )
    return findings, "executed", None


RULES = {"PRIV-001": priv_001, "PRIV-002": priv_002}
