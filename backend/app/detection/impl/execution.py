# detection/impl/execution.py - Reglas EXEC-001..007.
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.detection.context import concat_text
from app.detection.findings import clip_text, new_finding
from app.detection.impl.auth import _host_key, _user_key

StateTuple = Tuple[List[Dict[str, Any]], str, Optional[str]]


def _match_any(text: str, patterns: List[str]) -> Optional[str]:
    """Prueba patterns (regex; si alguno no compila, comparacion literal). Devuelve el patrón que matcheó."""
    import re

    for pat in patterns:
        try:
            if re.search(pat, text, re.IGNORECASE):
                return pat
        except re.error:
            if pat.casefold() in text.casefold():
                return pat
    return None


def _grouped_findings(
    matched: List[Tuple[Any, Dict[str, Any]]],
    key_fn: Callable[[Dict[str, Any]], Tuple],
    span_min: int,
    builder: Callable[[List[Tuple[Any, Dict[str, Any]]]], Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Agrupa los eventos matcheados por clave y ventana y genera hallazgos."""
    span = timedelta(minutes=span_min)
    groups: Dict[Tuple, List[Tuple[Any, Dict[str, Any]]]] = {}
    for dt, ev in matched:
        groups.setdefault(key_fn(ev), []).append((dt, ev))
    out: List[Dict[str, Any]] = []
    for _, items in sorted(groups.items(), key=lambda kv: (kv[1][0][0], kv[0])):
        items.sort(key=lambda x: (x[0], str(x[1].get("log_id"))))
        window = [items[0]]
        for item in items[1:]:
            if item[0] - window[0][0] <= span:
                window.append(item)
            else:
                out.append(builder(window))
                window = [item]
        out.append(builder(window))
    return [f for f in out if f]


# --------------------------- EXEC-001 ---------------------------

def exec_001(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}

    def pred(ev):
        text = concat_text(ev, ["process_command_line"])
        return bool(text) and _match_any(text, p.get("cmd_patterns") or []) is not None

    def builder(window):
        evs = [ev for _, ev in window]
        first = evs[0]
        hechos = [
            f"PowerShell con banderas de evasión ejecutado por {first.get('user_raw') or 'identidad no declarada'} "
            f"en {first.get('host_raw') or 'host no declarado'} a las {first['_ts'].isoformat()}.",
            f"Línea de comando: \"{clip_text(first.get('process_command_line'))}\".",
        ]
        return new_finding(
            cursor=state["cursor"],
            rule=rule,
            events=evs,
            hecho=hechos,
            inferencia=["Las banderas de ofuscación o bypass esconden el payload; la cadena exacta no pudo validarse con los logs."],
        )

    matched = [(dt, ev) for dt, ev in ctx.matching(pred)]
    out = _grouped_findings(matched, lambda ev: (_user_key(ev) or "", _host_key(ev)), 30, builder)
    return (out, "executed", None) if out else ([], "executed_no_findings", None)


# --------------------------- EXEC-002 ---------------------------

def exec_002(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    span_min = int(p.get("window_minutes", 30))

    def pred(ev):
        text = concat_text(ev, ["process_command_line", "event_description"])
        return bool(text) and _match_any(text, p.get("cmd_patterns") or []) is not None

    def builder(window):
        evs = [ev for _, ev in window]
        first = evs[0]
        hecho = [
            f"Ejecución de utilidades de reconocimiento por {first.get('user_raw') or 'identidad no declarada'} "
            f"en {first.get('host_raw') or 'host no declarado'} ({len(evs)} evento(s) entre "
            f"{window[0][0].isoformat()} y {window[-1][0].isoformat()})."
        ]
        cmds = [clip_text(e.get("process_command_line") or e.get("event_description")) for e in evs[:3]]
        hechos = hecho + [f"Comandos observados: {'; '.join(cmds)}."]
        return new_finding(cursor=state["cursor"], rule=rule, events=evs, hecho=hechos)

    matched = [(dt, ev) for dt, ev in ctx.matching(pred)]
    out = _grouped_findings(matched, lambda ev: (_user_key(ev) or "", _host_key(ev)), span_min, builder)
    return (out, "executed", None) if out else ([], "executed_no_findings", None)


# --------------------------- EXEC-003 ---------------------------

def exec_003(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}

    def pred(ev):
        text = concat_text(ev, ["process_command_line", "event_description"])
        return bool(text) and _match_any(text, p.get("cmd_patterns") or []) is not None

    findings = []
    for dt, ev in ctx.matching(pred):
        hecho = [
            f"Binario dual-use ejecutado por {ev.get('user_raw') or 'identidad no declarada'} "
            f"en {ev.get('host_raw') or 'host no declarado'} a las {dt.isoformat()}."
        ]
        findings.append(new_finding(cursor=state["cursor"], rule=rule, events=[ev], hecho=hecho))
    return (findings, "executed", None) if findings else ([], "executed_no_findings", None)


# --------------------------- EXEC-004 ---------------------------

def exec_004(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}

    def pred(ev):
        text = concat_text(ev, ["process_command_line"])
        return bool(text) and _match_any(text, p.get("cmd_patterns") or []) is not None

    findings = []
    for dt, ev in ctx.matching(pred):
        hechos = [
            f"Borrado de copias de sombra ejecutado por {ev.get('user_raw') or 'identidad no declarada'} "
            f"en {ev.get('host_raw') or 'host no declarado'} a las {dt.isoformat()}.",
            f"Línea de comando: \"{clip_text(ev.get('process_command_line'))}\".",
        ]
        findings.append(
            new_finding(
                cursor=state["cursor"],
                rule=rule,
                events=[ev],
                hecho=hechos,
                inferencia=["El borrado de sombras se asocia a ransomware o destructividad; verificar recuperación y copias disponibles."],
            )
        )
    return (findings, "executed", None) if findings else ([], "executed_no_findings", None)


# --------------------------- EXEC-005 (staging) ---------------------------

def exec_005(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    staging = [s.casefold() for s in p.get("staging_tokens") or []]
    sensitive = [s.casefold() for s in p.get("sensitive_tokens") or []]

    def pred(ev):
        text = concat_text(ev, ["process_command_line"])
        if not text or _match_any(text, p.get("archive_patterns") or []) is None:
            return False
        lowered = text.casefold()
        return any(tok in lowered for tok in staging) or any(tok in lowered for tok in sensitive)

    findings = []
    for dt, ev in ctx.matching(pred):
        text = concat_text(ev, ["process_command_line"])
        tokens = [tok for tok in staging + sensitive if tok in text.casefold()]
        hechos = [
            f"Creación de contenedor de archivo por {ev.get('user_raw') or 'identidad no declarada'} "
            f"en {ev.get('host_raw') or 'host no declarado'} a las {dt.isoformat()}.",
            f"Línea de comando: \"{clip_text(ev.get('process_command_line'))}\" "
            f"(rutas de staging o sensibles detectadas: {', '.join(sorted(set(tokens)))}).",
        ]
        findings.append(new_finding(cursor=state["cursor"], rule=rule, events=[ev], hecho=hechos))
    return (findings, "executed", None) if findings else ([], "executed_no_findings", None)


# --------------------------- EXEC-006 ---------------------------

def exec_006(ctx, rule, state) -> StateTuple:
    p = rule.parameters or {}
    paths = [s.casefold() for s in p.get("non_standard_paths") or []]

    def pred(ev):
        cmd = ev.get("process_command_line")
        if not cmd:
            return False
        lowered = str(cmd).casefold()
        return ".exe" in lowered and any(tok in lowered for tok in paths)

    matched = [(dt, ev) for dt, ev in ctx.matching(pred)]
    groups: Dict[Tuple, List[Tuple[Any, Dict[str, Any]]]] = {}
    for dt, ev in matched:
        k = (_user_key(ev) or "", _host_key(ev), str(ev.get("process_command_line") or "").casefold())
        groups.setdefault(k, []).append((dt, ev))
    findings = []
    for (user, host, cmd), items in groups.items():
        evs = [ev for _, ev in items]
        hechos = [
            f"Binario en ruta no estándar ejecutado {len(evs)} vez/veces por {evs[0].get('user_raw')} "
            f"en {evs[0].get('host_raw') or 'host no declarado'} (primera ejecución: {items[0][0].isoformat()}).",
            f"Comando: \"{clip_text(evs[0].get('process_command_line'))}\".",
        ]
        findings.append(new_finding(cursor=state["cursor"], rule=rule, events=evs, hecho=hechos))
    return (findings, "executed", None) if findings else ([], "executed_no_findings", None)


# --------------------------- EXEC-007 ---------------------------

def exec_007(ctx, rule, state) -> StateTuple:
    import re

    p = rule.parameters or {}
    ps_codes = {str(c) for c in p.get("ps_block_codes") or []}
    pairs = [(str(a).casefold(), str(b).casefold()) for a, b in p.get("parent_child_pairs") or []]
    block_patterns = ["Get-", "Set-", "New-", "invoke", "iex", "irm", "download", "encoded", "bypass"]
    RE_PARENT = re.compile(r"parent\s*=\s*([\w.\-]+)", re.IGNORECASE)

    def reason(ev) -> Optional[str]:
        if str(ev.get("event_code") or "") in ps_codes:
            text = concat_text(ev, ["process_command_line", "event_description"])
            if any(tok.casefold() in text.casefold() for tok in block_patterns):
                return "4104"
        desc = ev.get("event_description") or ""
        proc = str(ev.get("process_name") or "").casefold()
        m = RE_PARENT.search(str(desc))
        if m:
            parent = m.group(1).casefold()
            for a, b in pairs:
                if parent == a and (b == "*" or proc == b):
                    return "parent_child"
        return None

    matched = [(dt, ev) for dt, ev in ctx.matching(lambda ev: reason(ev) is not None)]

    def builder(window):
        evs = [ev for _, ev in window]
        hechos = [
            f"Cadena de ejecución anómala por {evs[0].get('user_raw')} en {evs[0].get('host_raw') or 'host no declarado'} "
            f"({len(evs)} evento(s) entre {window[0][0].isoformat()} y {window[-1][0].isoformat()})."
        ]
        detalles = []
        if any(reason(e) == "4104" for e in evs):
            detalles.append("registro PowerShell 4104 con contenido relevante")
        if any(reason(e) == "parent_child" for e in evs):
            detalles.append("relación padre-hijo inusual")
        hechos.append("Motivo(s): " + "; ".join(detalles) + ".")
        return new_finding(
            cursor=state["cursor"],
            rule=rule,
            events=evs,
            hecho=hechos,
            inferencia=["Las cadenas de ofimática→ejecutable o cmd→powershell han sido vectores iniciales habituales."],
        )

    out = _grouped_findings(matched, lambda ev: (_user_key(ev) or "", _host_key(ev)), int(p.get("window_minutes", 30)), builder)
    return (out, "executed", None) if out else ([], "executed_no_findings", None)


RULES = {
    "EXEC-001": exec_001,
    "EXEC-002": exec_002,
    "EXEC-003": exec_003,
    "EXEC-004": exec_004,
    "EXEC-005": exec_005,
    "EXEC-006": exec_006,
    "EXEC-007": exec_007,
}
