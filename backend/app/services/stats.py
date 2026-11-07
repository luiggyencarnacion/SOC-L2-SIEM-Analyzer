# services/stats.py - Agregados deterministas para el dashboard (fase D).
# Todo se calcula desde los eventos normalizados y los resultados del motor
# (deteccion + correlacion) ya presentes en memoria. Sin IA y sin hardcodear
# senales del archivo de ejemplo: los valores salen de los datos cargados.
from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

# Orden canonico de severidades del PLAN (7.1); valores fuera de esta lista
# se colocan despues, en orden alfabetico. Es vocabulario de dominio generico,
# no una senal del archivo de ejemplo.
SEVERITY_ORDER = ("Crítico", "Alto", "Medio", "Bajo")

# Umbral para cambiar la granularidad del eje temporal: con muchos dias, la
# serie por horas seria ilegible y se pasa a dias. Determinista.
MAX_HOURLY_BUCKETS = 192  # 8 dias por hora


def parse_iso(value: Any) -> Optional[datetime]:
    """Convierte un timestamp ISO a datetime; devuelve None si no se puede."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _top(counter: Counter, top_n: int) -> List[Dict[str, Any]]:
    """Top-N determinista: por conteo descendente y valor ascendente en empates."""
    items = sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))
    return [{"value": str(v), "count": c} for v, c in items[:top_n]]


def _non_empty(values: List[Any]) -> List[str]:
    return [str(v) for v in values if v not in (None, "")]


def _ordered_severities(present: List[str]) -> List[str]:
    known = [s for s in SEVERITY_ORDER if s in present]
    extra = sorted(s for s in present if s not in SEVERITY_ORDER)
    return known + extra


def _event_time_range(events: List[Dict[str, Any]]) -> Dict[str, Optional[str]]:
    parsed = [parse_iso(e.get("timestamp_parsed")) for e in events]
    valid = [p for p in parsed if p is not None]
    if not valid:
        return {"start": None, "end": None}
    # Sin conversion de zona horaria (PLAN 4.3): se comparan los valores tal cual.
    naive = [p.replace(tzinfo=None) for p in valid]
    return {"start": min(naive).isoformat(), "end": max(naive).isoformat()}


def _timeline(
    events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Serie temporal de eventos: buckets por hora (o por dia si el rango es largo)."""
    parsed: List[datetime] = []
    for e in events:
        ts = parse_iso(e.get("timestamp_parsed"))
        if ts is not None:
            parsed.append(ts.replace(tzinfo=None))
    if not parsed:
        return {"granularity": "hour", "buckets": [], "total": 0}
    start, end = min(parsed), max(parsed)
    hours_span = int((end - start).total_seconds() // 3600) + 1
    granularity = "hour" if hours_span <= MAX_HOURLY_BUCKETS else "day"
    counter: Counter = Counter()
    for ts in parsed:
        if granularity == "hour":
            counter[ts.replace(minute=0, second=0, microsecond=0).isoformat()] += 1
        else:
            counter[ts.date().isoformat()] += 1
    buckets = [{"bucket": k, "count": counter[k]} for k in sorted(counter)]
    return {"granularity": granularity, "buckets": buckets, "total": len(parsed)}


def _heatmap(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Matriz dia x hora (0-23) de eventos, para el heatmap del dashboard."""
    counter: Counter = Counter()
    for e in events:
        ts = parse_iso(e.get("timestamp_parsed"))
        if ts is None:
            continue
        counter[(ts.date().isoformat(), ts.hour)] += 1
    days = sorted({day for day, _ in counter})
    cells = [
        {"day": day, "hour": hour, "count": counter[(day, hour)]}
        for day in days
        for hour in sorted(h for d, h in counter if d == day)
    ]
    return {"days": days, "cells": cells, "total": sum(counter.values())}


def _siem_vs_calculated(
    events: List[Dict[str, Any]], findings: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Comparacion de la severidad declarada por el SIEM (eventos) contra la
    severidad calculada por el motor determinista (hallazgos). Unidades distintas:
    eventos vs hallazgos; el grafico las muestra como series separadas."""
    siem_counter: Counter = Counter(_non_empty([e.get("severity_siem") for e in events]))
    calc_counter: Counter = Counter(
        _non_empty([f.get("severity") for f in findings])
    )
    categories = _ordered_severities(list(siem_counter) + list(calc_counter))
    return {
        "categories": categories,
        "siem_events": [siem_counter.get(c, 0) for c in categories],
        "calculated_findings": [calc_counter.get(c, 0) for c in categories],
    }


def _quality_alerts(result: Any, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    quality = result.quality or {}
    flags = Counter(f for e in events for f in (e.get("quality_flags") or []))
    ts = quality.get("timestamp") or {}
    return {
        # El reporte de calidad ya contabiliza los timestamps invalidos.
        "invalid_timestamps": int(ts.get("invalid", 0) or 0),
        "missing_timestamps": int(ts.get("missing", 0) or 0),
        "invalid_source_ips": int(flags.get("source_ip_invalid", 0)),
        "synthetic_log_ids": int(flags.get("log_id_synthetic", 0)),
        "duplicate_log_ids": len(quality.get("duplicate_log_ids") or []),
        "mixed_type_columns": len(quality.get("mixed_type_columns") or []),
    }


def build_stats(result: Any, top_n: int = 10) -> Dict[str, Any]:
    """Construye el resumen del dashboard para un AnalysisResult ya ejecutado."""
    events: List[Dict[str, Any]] = list(result.events or [])
    det = result.detection or {}
    corr = result.correlation or {}
    findings: List[Dict[str, Any]] = list(det.get("findings") or [])
    coverage: List[Dict[str, Any]] = list(det.get("coverage") or [])
    summary = det.get("summary") or {}
    incidents: List[Dict[str, Any]] = list(corr.get("incidents") or [])
    corr_summary = corr.get("summary") or {}

    severity_counts = dict(summary.get("findings_by_severity") or {})
    if not severity_counts and findings:
        severity_counts = dict(Counter(f.get("severity") for f in findings))

    incidents_by_band = dict(corr_summary.get("incidents_by_band") or {})
    if not incidents_by_band and incidents:
        incidents_by_band = dict(Counter(i.get("band") for i in incidents))

    mitre_counter: Counter = Counter()
    for f in findings:
        for technique in f.get("mitre") or []:
            mitre_counter[str(technique)] += 1

    rules_skipped = (
        int(summary.get("rules_skipped_disabled", 0) or 0)
        + int(summary.get("rules_skipped_missing_fields", 0) or 0)
        + int(summary.get("rules_insufficient_data", 0) or 0)
    )

    timeline = _timeline(events)
    heatmap = _heatmap(events)
    quality = result.quality or {}
    result_distribution = dict(
        quality.get("result_distribution")
        or Counter(e.get("result_norm") or "other" for e in events)
    )

    return {
        "sheet": result.sheet,
        "kpis": {
            "total_events": len(events),
            "events_with_timestamp": timeline["total"],
            "total_findings": int(summary.get("total_findings", len(findings)) or len(findings)),
            "findings_by_severity": severity_counts,
            "total_incidents": int(corr_summary.get("total_incidents", len(incidents)) or len(incidents)),
            "incidents_by_band": incidents_by_band,
            "affected_users": len(set(_non_empty([e.get("user_raw") for e in events]))),
            "affected_hosts": len(set(_non_empty([e.get("host_raw") for e in events]))),
            "affected_source_ips": len(set(_non_empty([e.get("source_ip") for e in events]))),
            "rules_total": int(summary.get("total_rules", len(coverage)) or len(coverage)),
            "rules_executed": int(summary.get("rules_executed", 0) or 0),
            "rules_skipped": rules_skipped,
            "rules_error": int(summary.get("rules_error", 0) or 0),
            "manual_overrides": len(result.overrides or {}),
            "quality_alerts": _quality_alerts(result, events),
            "time_range": _event_time_range(events),
        },
        "events_timeline": timeline,
        "top": {
            "source_ips": _top(Counter(_non_empty([e.get("source_ip") for e in events])), top_n),
            "users": _top(Counter(_non_empty([e.get("user_raw") for e in events])), top_n),
            "hosts": _top(Counter(_non_empty([e.get("host_raw") for e in events])), top_n),
            "event_codes": _top(Counter(_non_empty([e.get("event_code") for e in events])), top_n),
            "log_sources": _top(Counter(_non_empty([e.get("log_source") for e in events])), top_n),
            "siem_severities": _top(Counter(_non_empty([e.get("severity_siem") for e in events])), top_n),
        },
        "siem_vs_calculated": _siem_vs_calculated(events, findings),
        "heatmap": heatmap,
        "mitre": _top(mitre_counter, len(mitre_counter) or 1),
        "result_distribution": result_distribution,
    }


def time_bounds(time_from: Optional[str], time_to: Optional[str]) -> Tuple[Optional[datetime], Optional[datetime]]:
    """Normaliza los limites temporales del filtro de eventos (fase D).

    Se comparan como hora de pared (se descarta el offset) para no introducir
    conversion de zona horaria, segun el PLAN 4.3. Lanza ValueError si un
    limite proporcionado no es una fecha ISO 8601 valida.
    """
    from_dt = _parse_required(time_from, "time_from")
    to_dt = _parse_required(time_to, "time_to")
    if from_dt is not None:
        from_dt = from_dt.replace(tzinfo=None)
    if to_dt is not None:
        to_dt = to_dt.replace(tzinfo=None)
    return from_dt, to_dt


def _parse_required(value: Optional[str], name: str) -> Optional[datetime]:
    if value in (None, ""):
        return None
    parsed = parse_iso(value)
    if parsed is None:
        raise ValueError(f"{name} no es una fecha ISO 8601 valida: {value!r}")
    return parsed


def in_time_range(row: Dict[str, Any], from_dt: Optional[datetime], to_dt: Optional[datetime]) -> bool:
    ts = parse_iso(row.get("timestamp_parsed"))
    if ts is None:
        return False
    ts = ts.replace(tzinfo=None)
    if from_dt is not None and ts < from_dt:
        return False
    if to_dt is not None and ts > to_dt:
        return False
    return True


def bucket_range(bucket: str, granularity: str) -> Tuple[str, str]:
    """Convierte un bucket del timeline en un rango [from, to) para el drill-down."""
    if granularity == "day":
        start = datetime.fromisoformat(bucket)
        end = start + timedelta(days=1)
    else:
        start = datetime.fromisoformat(bucket)
        end = start + timedelta(hours=1)
    return start.isoformat(), (end - timedelta(seconds=1)).isoformat()
