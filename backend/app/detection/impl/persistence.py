# detection/impl/persistence.py - Reglas PERS-001..003.
import re
from typing import Any, Dict, List, Optional, Tuple

from app.detection.context import concat_text
from app.detection.findings import clip_text, new_finding
from app.detection.impl.auth import _host_key, _user_key

StateTuple = Tuple[List[Dict[str, Any]], str, Optional[str]]


def _code(ev: Dict[str, Any]) -> str:
    return str(ev.get("event_code") or "")


def _find_kv(text: str, key: str) -> Optional[str]:
    m = re.search(rf"{key}\s*=\s*([^;]+)", text, re.IGNORECASE)
    return m.group(1).strip() if m else None


def pers_001(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    events = [ev for _, ev in ctx.matching(lambda ev: _code(ev) in {str(c) for c in p.get("codes") or []})]
    findings = []
    for ev in events:
        text = concat_text(ev, ["process_command_line", "event_description"])
        task_name = ev.get("task_name") or _find_kv(text, "TaskName")
        action = _find_kv(text, "Action")
        hechos = [
            f"Tarea programada creada (4698) por {ev.get('user_raw') or 'identidad no declarada'} "
            f"en {ev.get('host_raw') or 'host no declarado'} a las {ev['_ts'].isoformat()}.",
        ]
        if task_name:
            hechos.append(f"Nombre de tarea: \"{task_name}\".")
        if action:
            hechos.append(f"Acción declarada: \"{clip_text(action)}\".")
        findings.append(new_finding(cursor=state["cursor"], rule=rule, events=[ev], hecho=hechos))
    return (findings, "executed", None) if findings else ([], "executed_no_findings", None)


def pers_002(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    events = [ev for _, ev in ctx.matching(lambda ev: _code(ev) in {str(c) for c in p.get("codes") or []})]
    findings = []
    for ev in events:
        text = concat_text(ev, ["process_command_line", "event_description"])
        service = ev.get("service_name") or _find_kv(text, "ServiceName")
        image = _find_kv(text, "ImagePath") or _find_kv(text, "BinaryPathName")
        hechos = [
            f"Servicio nuevo instalado ({' / '.join(sorted({str(c) for c in p.get('codes') or []}))}) "
            f"por {ev.get('user_raw') or 'identidad no declarada'} en {ev.get('host_raw') or 'host no declarado'} "
            f"a las {ev['_ts'].isoformat()}.",
        ]
        if service:
            hechos.append(f"Nombre del servicio: \"{service}\".")
        if image:
            hechos.append(f"Binario declarado: \"{clip_text(image)}\".")
        findings.append(
            new_finding(
                cursor=state["cursor"],
                rule=rule,
                events=[ev],
                hecho=hechos,
                inferencia=["Un servicio nuevo apuntando a un binario propio es un mecanismo clásico de persistencia."],
            )
        )
    return (findings, "executed", None) if findings else ([], "executed_no_findings", None)


def pers_003(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    codes = {str(c) for c in p.get("codes") or []}
    min_exec = int(p.get("min_executions", 4))
    max_interval = int(p.get("max_interval_minutes", 30))
    groups: Dict[Tuple, List[Any]] = {}
    for dt, ev in ctx.matching(lambda ev: _code(ev) in codes and ev.get("process_command_line")):
        k = (_user_key(ev) or "", _host_key(ev), str(ev.get("process_command_line")).casefold())
        groups.setdefault(k, []).append(ev)
    findings = []
    for (user, host, cmd), evs in groups.items():
        evs = sorted(evs, key=lambda e: (e["_ts"], str(e.get("log_id"))))
        if len(evs) < min_exec:
            continue
        intervals = [(evs[i]["_ts"] - evs[i - 1]["_ts"]).total_seconds() / 60.0 for i in range(1, len(evs))]
        if any(interval > max_interval for interval in intervals):
            continue
        hecho = [
            f"{len(evs)} ejecuciones encadenadas de la misma línea de comando por {evs[0].get('user_raw')} "
            f"en {evs[0].get('host_raw') or 'host no declarado'} entre {evs[0]['_ts'].isoformat()} y {evs[-1]['_ts'].isoformat()}.",
            f"Comando: \"{clip_text(evs[0].get('process_command_line'))}\"; intervalos (min): "
            f"{', '.join(f'{i:.0f}' for i in intervals)}.",
        ]
        findings.append(
            new_finding(
                cursor=state["cursor"], rule=rule, events=evs, hecho=hecho,
                inferencia=["La cadencia regular de la misma ejecución refleja un agente o tarea persistente que refresca el payload."],
            )
        )
    return (findings, "executed", None) if findings else ([], "executed_no_findings", None)


RULES = {"PERS-001": pers_001, "PERS-002": pers_002, "PERS-003": pers_003}
