# reporting/exports.py - Exportaciones de la fase F (PLAN seccion 9):
#   - IoCs a CSV con proteccion contra inyeccion de formulas (prefijo "'" en
#     celdas que empiezan por =, +, - o @, PLAN seccion 11).
#   - Hallazgos a JSON (estructura determinista del motor, sin redaccion).
import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

_DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(value: Any) -> str:
    """Neutraliza inyeccion de formulas: prefijo "'" en celdas peligrosas."""
    s = "" if value is None else str(value)
    if s.startswith(_DANGEROUS_PREFIXES):
        return "'" + s
    return s


_IOC_LABELS_ES = {
    "ips": "IP pública", "hosts": "Host", "urls": "URL", "cuentas": "Cuenta",
    "shares": "Share SMB", "rutas": "Ruta/archivo", "servicios_tareas": "Servicio/Tarea",
    "hashes": "Hash",
}


def iocs_csv(result) -> str:
    """CSV de IoCs: tipo (en español), valor e incidentes donde aparece cada indicador."""
    incidents = list((result.correlation or {}).get("incidents", []))
    aggregated: Dict[str, Dict[str, Any]] = {}
    for inc in incidents:
        for kind, values in (inc.get("iocs") or {}).items():
            for v in values or []:
                v = str(v).strip()
                if not v or v == "-":
                    continue
                key = f"{kind}\u241f{v}"
                entry = aggregated.setdefault(key, {"tipo": _IOC_LABELS_ES.get(kind, kind), "valor": v, "incidentes": []})
                entry["incidentes"].append(str(inc.get("incident_id")))

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow(["tipo", "valor", "incidentes"])
    for entry in sorted(aggregated.values(), key=lambda e: (e["tipo"], e["valor"])):
        writer.writerow([
            sanitize_csv_cell(entry["tipo"]),
            sanitize_csv_cell(entry["valor"]),
            sanitize_csv_cell("; ".join(sorted(set(entry["incidentes"])))),
        ])
    return buf.getvalue()


def findings_json(result) -> str:
    """JSON de hallazgos: estructura del motor + score/override (fase C), sin texto libre."""
    findings: List[Dict[str, Any]] = [dict(f) for f in (result.detection or {}).get("findings", [])]
    for f in findings:
        ov = getattr(result, "overrides", {}).get(f"finding:{f.get('finding_id')}")
        if ov:
            f["override"] = ov
    payload = {
        "sheet": result.sheet,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "findings": findings,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)
