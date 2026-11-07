# detection/impl/exfil.py - Reglas EXF-001..004.
from typing import Any, Dict, List, Optional, Tuple

from app.detection.context import concat_text
from app.detection.findings import clip_text, new_finding
from app.detection.impl.auth import _host_key, _user_key

StateTuple = Tuple[List[Dict[str, Any]], str, Optional[str]]


def _code(ev: Dict[str, Any]) -> str:
    return str(ev.get("event_code") or "")


def _dest_is_public(ev: Dict[str, Any]) -> bool:
    """El scope del destino se resuelve con la misma clasificacion de normalize."""
    from app.ingestion.normalize import validate_ip

    dst_ip = ev.get("destination_ip")
    if dst_ip:
        _, scope = validate_ip(str(dst_ip))
        return scope == "public"
    return False


def exf_001(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    connection_code = str(p.get("connection_code", "5156"))
    unusual = [s.casefold() for s in p.get("unusual_processes") or []]

    def pred(ev):
        if _code(ev) != connection_code:
            return False
        if not _dest_is_public(ev):
            return False
        proc = str(ev.get("process_name") or "").casefold()
        text = concat_text(ev, ["process_command_line", "event_description"]).casefold()
        return any(tok in proc for tok in unusual) or any(tok in text for tok in unusual)

    findings = []
    for dt, ev in ctx.matching(pred):
        hechos = [
            f"Conexión permitida ({connection_code}) a destino externo {ev.get('destination_raw') or 'no declarado'} "
            f"desde el host {ev.get('host_raw') or 'host no declarado'} a las {dt.isoformat()} "
            f"con proceso {ev.get('process_name') or 'no declarado'}."
        ]
        findings.append(
            new_finding(
                cursor=state["cursor"], rule=rule, events=[ev], hecho=hechos,
                inferencia=["La salida externa de un servidor por binario administrativo puede abrir un canal de C2 o exfiltración."],
            )
        )
    return (findings, "executed", None) if findings else ([], "executed_no_findings", None)


def exf_002(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    post_words = [s.casefold() for s in p.get("post_words") or []]
    bytes_threshold = int(p.get("bytes_threshold_mb", 50)) * 1024 * 1024

    def pred(ev):
        desc = str(ev.get("event_description") or "").casefold()
        method = str(ev.get("http_method") or "").casefold()
        if any(w in desc for w in post_words) or method == "post":
            return True
        return ev.get("bytes_out") is not None

    matched = [(dt, ev) for dt, ev in ctx.matching(pred)]
    groups: Dict[Tuple, List[Any]] = {}
    for dt, ev in matched:
        k = (_user_key(ev) or "", _host_key(ev), str(ev.get("destination_raw") or ev.get("destination_ip") or ""))
        groups.setdefault(k, []).append(ev)
    findings = []
    import re

    bytes_re = re.compile(str(p.get("bytes_pattern") or "bytes_out\\s*=\\s*(\\d+)"), re.IGNORECASE)
    for (user, host, dest), evs in groups.items():
        evs = sorted(evs, key=lambda e: (e["_ts"], str(e.get("log_id"))))
        posts = [e for e in evs if any(w in str(e.get("event_description") or "").casefold() for w in post_words) or str(e.get("http_method") or "").casefold() == "post"]
        total_bytes = 0
        for e in evs:
            if e.get("bytes_out") is not None:
                total_bytes += int(e["bytes_out"])
            else:
                m = bytes_re.search(concat_text(e, ["process_command_line"]))
                if m:
                    total_bytes += int(m.group(1))
        if len(posts) < int(p.get("min_posts", 3)) and total_bytes < bytes_threshold:
            continue
        hechos = [
            f"{len(posts)} peticiones POST salientes hacia {dest} por {evs[0].get('user_raw')} "
            f"desde {evs[0].get('host_raw') or 'host no declarado'} "
            f"({evs[0]['_ts'].isoformat()} → {evs[-1]['_ts'].isoformat()}).",
            f"Volumen total saliente: {total_bytes:,} bytes (umbral: {p.get('bytes_threshold_mb')} MB).",
        ]
        hechos.append(f"Línea de comando de la primera: \"{clip_text(evs[0].get('process_command_line'))}\".")
        findings.append(
            new_finding(
                cursor=state["cursor"], rule=rule, events=evs, hecho=hechos,
                factors=["volumen_grande"] if total_bytes >= bytes_threshold else [],
                inferencia=["La repetición de POSTs con volumen hacia el mismo destino externo es firma típica de exfiltración."],
            )
        )
    return (findings, "executed", None) if findings else ([], "executed_no_findings", None)


def exf_003(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    words = [s.casefold() for s in p.get("upload_words") or []]
    min_up = int(p.get("min_uploads", 5))
    max_interval = int(p.get("max_interval_minutes", 30))

    def pred(ev):
        text = concat_text(ev, ["event_description", "process_command_line"]).casefold()
        return any(w in text for w in words)

    groups: Dict[Tuple, List[Any]] = {}
    for dt, ev in ctx.matching(pred):
        k = (_user_key(ev) or "", _host_key(ev), str(ev.get("destination_raw") or ev.get("destination_ip") or ""))
        groups.setdefault(k, []).append(ev)
    findings = []
    for (user, host, dest), evs in groups.items():
        evs = sorted(evs, key=lambda e: (e["_ts"], str(e.get("log_id"))))
        if len(evs) < min_up:
            continue
        intervals = [(evs[i]["_ts"] - evs[i - 1]["_ts"]).total_seconds() / 60.0 for i in range(1, len(evs))]
        if any(i > max_interval for i in intervals):
            continue
        hecho = [
            f"{len(evs)} subidas recurrentes hacia {dest} por {evs[0].get('user_raw')} en "
            f"{evs[0].get('host_raw') or 'host no declarado'} con cadencia <= {max_interval} min "
            f"({evs[0]['_ts'].isoformat()} → {evs[-1]['_ts'].isoformat()})."
        ]
        findings.append(
            new_finding(
                cursor=state["cursor"], rule=rule, events=evs, hecho=hecho,
                inferencia=["Las recurrencias hacia el mismo destino externo marcan un canal estructurado de subida."],
            )
        )
    return (findings, "executed", None) if findings else ([], "executed_no_findings", None)


def exf_004(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    obj_code = str(p.get("object_code", "4663"))
    sensitive = [s.casefold() for s in p.get("sensitive_tokens") or []]
    min_reads = int(p.get("min_reads", 10))

    def pred(ev):
        if _code(ev) != obj_code:
            return False
        text = concat_text(ev, ["process_command_line", "file_path", "share", "destination_raw"]).casefold()
        return any(tok in text for tok in sensitive)

    groups: Dict[Tuple, List[Any]] = {}
    for dt, ev in ctx.matching(pred):
        text = concat_text(ev, ["process_command_line", "file_path"])
        base = None
        for word in p.get("prefix_words") or []:
            idx = text.casefold().find(word)
            if idx >= 0:
                base = str(ev.get("process_command_line"))[idx + len(word):].strip()
                break
        if not base and ev.get("file_path"):
            base = str(ev.get("file_path"))
        base = base or "ruta no declarada"
        dir_part = base.rsplit("\\", 1)[0] if "\\" in base else base.rsplit("/", 1)[0]
        k = (_user_key(ev) or "", _host_key(ev), dir_part)
        groups.setdefault(k, []).append(ev)
    findings = []
    for (user, host, dir_part), evs in groups.items():
        evs = sorted(evs, key=lambda e: (e["_ts"], str(e.get("log_id"))))
        if len(evs) < min_reads:
            continue
        hecho = [
            f"{len(evs)} accesos (4663) del usuario {evs[0].get('user_raw')} a la carpeta \"{dir_part}\" "
            f"sobre {evs[0].get('host_raw') or 'host no declarado'} entre {evs[0]['_ts'].isoformat()} "
            f"y {evs[-1]['_ts'].isoformat()} (umbral de lectura masiva: {min_reads})."
        ]
        hechos = [hecho] + [f"Ruta de detalle: \"{clip_text(texto_l)}\"." for texto_l in [str(evs[0].get("process_command_line") or evs[0].get("file_path") or "")]]
        ids = ", ".join(str(e.get("log_id")) for e in evs[: min(5, len(evs))])
        if len(evs) > 5:
            hechos.append(f"Ejemplos de Log_ID: {ids} (y {len(evs) - 5} más).")
        else:
            hechos.append(f"Log_ID(s): {ids}.")
        findings.append(
            new_finding(
                cursor=state["cursor"], rule=rule, events=evs, hecho=hechos,
                inferencia=["La lectura masiva y rápida en una carpeta sensible es la fase de recolección previa a la exfiltración."],
                factors=["acceso_a_datos_sensibles"],
            )
        )
    return (findings, "executed", None) if findings else ([], "executed_no_findings", None)


RULES = {"EXF-001": exf_001, "EXF-002": exf_002, "EXF-003": exf_003, "EXF-004": exf_004}
