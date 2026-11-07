# detection/engine.py - Motor determinista: ejecuta reglas en orden y produce hallazgos + cobertura.
# Politicas (PLAN seccion 6.3 y 12): sin IA; sin hardcoding; cobertura por regla;
# orden especial AUTH-002 antes de AUTH-001/AUTH-004 para la absorcion del spraying.
import time
from typing import Any, Dict, List, Optional

from app.detection.context import Context
from app.detection.findings import FindingCursor
from app.detection.impl import handler_for
from app.detection.loader import RuleConfig, load_rules_cached

# Orden de ejecucion: AUTH-002 primero (absorcion), luego el resto por categoria.
RULE_ORDER_OVERRIDE = {"AUTH-002": -100, "AUTH-001": -50, "AUTH-004": -49}


def sort_rules(rules: List[RuleConfig]) -> List[RuleConfig]:
    return sorted(rules, key=lambda r: (RULE_ORDER_OVERRIDE.get(r.id, 0), r.id))


def required_field_missing(rule: RuleConfig, ctx: Context) -> Optional[str]:
    """Comprueba que el dataset tiene el campo obligatorio con al menos un valor."""
    for field in rule.required_fields:
        has_value = any(
            e.get(field) not in (None, "") for e in ctx.events
        ) or any(
            e.get(alias) not in (None, "") for e in ctx.events
            for alias in _FIELD_ALIASES.get(field, ())
        )
        if not has_value:
            return field
    return None


_FIELD_ALIASES = {
    "ts": ("timestamp_parsed",),
    "user": ("user_key", "user_raw"),
    "host": ("host_key", "host_raw"),
    "src_ip": ("source_ip",),
    "dst": ("destination_host", "destination_ip", "destination_raw"),
    "event_code": ("event_code",),
    "result": ("result_norm",),
    "cmd": ("process_command_line",),
    "msg": ("event_description",),
    "logon_type": ("logon_type",),
    "http": ("http_status", "http_method"),
    "share": ("share",),
    "file_path": ("file_path",),
    "bytes_out": ("bytes_out",),
    "task_service": ("task_name", "service_name"),
}


def run_detection(events: List[Dict[str, Any]], rules_path: Optional[str] = None) -> Dict[str, Any]:
    """Ejecuta el motor sobre eventos normalizados. Devuelve {findings, coverage, summary}."""
    start = time.perf_counter()
    rules = sort_rules(load_rules_cached(rules_path))
    ctx = Context(events)
    cursor = FindingCursor()
    state: Dict[str, Any] = {"cursor": cursor}
    findings: List[Dict[str, Any]] = []
    coverage: List[Dict[str, Any]] = []

    for rule in rules:
        entry: Dict[str, Any] = {"rule_id": rule.id, "rule_name": rule.name}
        if not rule.enabled:
            entry.update(status="skipped_disabled", reason="regla deshabilitada en la configuracion", findings=0)
            coverage.append(entry)
            continue
        handler = handler_for(rule.id)
        if handler is None:
            entry.update(status="error", reason="regla sin implementacion en el motor", findings=0)
            coverage.append(entry)
            continue
        missing = required_field_missing(rule, ctx)
        if missing is not None:
            entry.update(
                status="skipped_missing_fields",
                reason=f"campo obligatorio '{missing}' ausente en todos los eventos",
                findings=0,
            )
            coverage.append(entry)
            continue
        try:
            rule_findings, status, reason = handler(ctx, rule, state)
        except Exception as exc:  # la cobertura no rompe el analisis
            entry.update(status="error", reason=f"error de ejecucion: {exc.__class__.__name__}", findings=0)
            coverage.append(entry)
            continue
        if status == "insufficient_data":
            entry.update(status="insufficient_data", reason=reason or "datos insuficientes", findings=0)
            coverage.append(entry)
            continue
        if status == "executed_no_findings":
            entry.update(status="executed_no_findings", reason=None, findings=0)
            coverage.append(entry)
            continue
        findings.extend(rule_findings)
        entry.update(status="executed", reason=None, findings=len(rule_findings))
        coverage.append(entry)

    ctx.drop_internal()
    findings.sort(key=lambda f: (f.get("time_range", {}).get("start") or "", f["finding_id"]))
    # Renumera F-001.. tras el orden temporal.
    for i, f in enumerate(findings, start=1):
        f["finding_id"] = f"F-{i:03d}"
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    by_severity: Dict[str, int] = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
    return {
        "findings": findings,
        "coverage": coverage,
        "summary": {
            "total_rules": len(rules),
            "rules_executed": sum(1 for c in coverage if c["status"] == "executed"),
            "rules_executed_no_findings": sum(1 for c in coverage if c["status"] == "executed_no_findings"),
            "rules_skipped_disabled": sum(1 for c in coverage if c["status"] == "skipped_disabled"),
            "rules_skipped_missing_fields": sum(1 for c in coverage if c["status"] == "skipped_missing_fields"),
            "rules_insufficient_data": sum(1 for c in coverage if c["status"] == "insufficient_data"),
            "rules_error": sum(1 for c in coverage if c["status"] == "error"),
            "total_findings": len(findings),
            "findings_by_severity": by_severity,
            "elapsed_ms": elapsed_ms,
        },
    }
