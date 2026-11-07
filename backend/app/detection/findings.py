# detection/findings.py - Constructor de hallazgos (Finding) con evidencia y afirmaciones.
# Reglas de oro (AGENTS.md): toda evidencia cita Log_ID reales; se marcan Hecho / Inferencia.
from typing import Any, Dict, List, Optional

from app.detection.loader import RuleConfig


class FindingCursor:
    """Asigna identificadores F-001.. a los hallazgos ordenados por tiempo."""

    def __init__(self) -> None:
        self._n = 0

    def next(self) -> str:
        self._n += 1
        return f"F-{self._n:03d}"


def clip_evidence(ids: List[str], limit: int) -> Dict[str, Any]:
    shown = ids[: max(1, limit)]
    return {
        "evidence_log_ids": shown,
        "total_evidence": len(ids),
        "evidence_omitted": max(0, len(ids) - len(shown)),
    }


def time_range(events: List[Dict[str, Any]]) -> Dict[str, Optional[str]]:
    times = [e.get("timestamp_parsed") for e in events if isinstance(e, dict) and e.get("timestamp_parsed")]
    if not times:
        return {"start": None, "end": None}
    return {"start": min(times), "end": max(times)}


def entities_of(events: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    ents: Dict[str, set] = {"users": set(), "hosts": set(), "source_ips": set(), "destinations": set()}
    for ev in events:
        for key, out in (
            ("user_raw", "users"),
            ("host_raw", "hosts"),
            ("source_ip", "source_ips"),
        ):
            val = ev.get(key)
            if val:
                ents[out].add(str(val))
        dest = ev.get("destination_host") or ev.get("destination_ip") or ev.get("destination_raw")
        if dest:
            ents["destinations"].add(str(dest))
    return {k: sorted(v) for k, v in ents.items()}


def fmt_user(event: Dict[str, Any]) -> str:
    return str(event.get("user_raw") or "identidad no declarada")


def fmt_host(event: Dict[str, Any]) -> str:
    return str(event.get("host_raw") or "host no declarado")


def fmt_ip(event: Dict[str, Any]) -> str:
    ip = event.get("source_ip")
    scope = event.get("source_ip_scope") or ""
    if not ip:
        return "origen no declarado"
    return f"{ip} ({scope})" if scope else str(ip)


def list_fmt(values: List[str], max_items: int = 5) -> str:
    if not values:
        return "ninguno"
    shown = values[:max_items]
    txt = ", ".join(shown)
    if len(values) > max_items:
        txt += f" y {len(values) - max_items} más"
    return txt


def clip_text(text: Any, max_chars: int = 120) -> str:
    s = str(text or "")
    return s if len(s) <= max_chars else s[: max_chars - 3] + "..."


def new_finding(
    cursor: FindingCursor,
    rule: RuleConfig,
    events: List[Dict[str, Any]],
    *,
    hecho: List[str],
    inferencia: Optional[List[str]] = None,
    hipotesis: Optional[List[str]] = None,
    factors: Optional[List[str]] = None,
    absorbed_detail: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    events = [e for e in events if isinstance(e, dict)]
    limit = rule.evidence_limit or 10
    ids = [str(e.get("log_id")) for e in events if e.get("log_id")]
    return {
        "finding_id": cursor.next(),
        "rule_id": rule.id,
        "rule_name": rule.name,
        "category": rule.category,
        "severity": rule.base_severity,
        "description": rule.description,
        "rationale": rule.rationale,
        "mitre": list(rule.mitre),
        "entities": entities_of(events),
        "total_events_matched": len(ids),
        **clip_evidence(ids, limit),
        "time_range": time_range(events),
        "factors": factors or [],
        "statements": {
            "hecho": hecho,
            "inferencia": inferencia or [],
            "hipotesis": hipotesis or [],
        },
        "absorbed_detail": absorbed_detail,
    }
