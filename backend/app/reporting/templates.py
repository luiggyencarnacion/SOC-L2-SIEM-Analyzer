# reporting/ - Plantillas deterministas de redaccion (fase E).
# La IA nunca detecta ni inventa: con AI_PROVIDER=none todo el texto sale de aqui,
# construido unicamente a partir de hallazgos e incidentes estructurados.
# Regla de oro: si un hallazgo no tiene evidencia, frase exacta obligatoria.
from typing import Any, Dict, List, Optional

NO_EVIDENCE_PHRASE = "No hay evidencia en los logs proporcionados."
SEVERITY_ORDER = ["Crítico", "Alto", "Medio", "Bajo"]
_MAX_CITATIONS = 8


def _paragraph(label: str, text: str, citations: Optional[List[str]] = None) -> Dict[str, Any]:
    return {
        "label": label,
        "text": text,
        "citations": [c for c in (citations or [])][:_MAX_CITATIONS],
        "source": "plantilla",
    }


def _fmt_list(values: List[str], max_items: int = 5) -> str:
    if not values:
        return "ninguna"
    shown = values[:max_items]
    txt = ", ".join(shown)
    if len(values) > max_items:
        txt += f" y {len(values) - max_items} más"
    return txt


def _fmt_range(time_range: Dict[str, Any]) -> str:
    start, end = time_range.get("start"), time_range.get("end")
    if not start and not end:
        return " (rango temporal no determinado)"
    return f" entre {start} y {end}"


def _sev_detail(findings: List[Dict[str, Any]]) -> str:
    counts: Dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity") or "Sin clase")
        counts[sev] = counts.get(sev, 0) + 1
    parts = []
    for sev in SEVERITY_ORDER + sorted(set(counts) - set(SEVERITY_ORDER)):
        if counts.get(sev):
            parts.append(f"{sev}: {counts[sev]}")
    return ", ".join(parts) if parts else "sin hallazgos"


def _evidence_of(f: Dict[str, Any]) -> List[str]:
    return list(f.get("evidence_log_ids") or [])


def executive_summary_paragraphs(
    result,
    findings: List[Dict[str, Any]],
    incidents: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    q = result.quality or {}
    ts = q.get("timestamp", {}) if isinstance(q.get("timestamp", {}), dict) else {}
    total_events = len(result.events)
    valid_ts = int(ts.get("total", 0) or 0)
    invalid_ts = int(ts.get("invalid", 0) or 0)
    missing_ts = int(ts.get("missing", 0) or 0)

    paragraphs: List[Dict[str, Any]] = []
    if not findings:
        paragraphs.append(_paragraph("Hecho", NO_EVIDENCE_PHRASE))
        paragraphs.append(_paragraph(
            "Hecho",
            f"Con la configuración actual el motor determinista no generó hallazgos sobre los "
            f"{total_events} eventos analizados; revisa la cobertura de reglas y la calidad de datos.",
        ))
        return paragraphs

    ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f.get("severity")) if f.get("severity") in SEVERITY_ORDER else 99, -(f.get("score") or 0)))
    top = ordered[:3]
    citations = [lid for f in top for lid in _evidence_of(f)][:3] or None
    paragraphs.append(_paragraph(
        "Hecho",
        f"Se analizaron {total_events} eventos de la hoja '{result.sheet}'. El motor determinista "
        f"generó {len(findings)} hallazgo(s) ({_sev_detail(findings)}) agrupados en "
        f"{len(incidents)} incidente(s).",
        citations,
    ))

    if incidents:
        ordered_inc = sorted(incidents, key=lambda i: -(i.get("score") or 0))[:3]
        parts = [
            f"{i.get('incident_id')} ({i.get('band')}, score {i.get('score')}) con {len(i.get('findings') or [])} hallazgo(s)"
            for i in ordered_inc
        ]
        inc_citations = []
        for i in ordered_inc:
            for member in i.get("findings") or []:
                f = next((x for x in findings if x.get("finding_id") == member), None)
                if f:
                    inc_citations.extend(_evidence_of(f))
        paragraphs.append(_paragraph(
            "Hecho",
            "Incidentes de mayor criticidad: " + "; ".join(parts) + ".",
            inc_citations[:_MAX_CITATIONS] or None,
        ))

    paragraphs.append(_paragraph(
        "Hecho",
        f"Calidad de los datos: {valid_ts} de {total_events} eventos con timestamp válido "
        f"({invalid_ts} inválidos, {missing_ts} sin timestamp). "
        "La severidad declarada por el SIEM no influye en el puntaje calculado.",
    ))
    return paragraphs


def finding_paragraphs(f: Dict[str, Any]) -> List[Dict[str, Any]]:
    evidence = _evidence_of(f)
    score = f.get("score")
    band = f.get("band") or f.get("severity")
    paragraphs: List[Dict[str, Any]] = []

    if not evidence:
        paragraphs.append(_paragraph("Hecho", NO_EVIDENCE_PHRASE))
        return paragraphs

    paragraphs.append(_paragraph(
        "Hecho",
        f"La regla {f.get('rule_id')} ({f.get('rule_name')}, categoría {f.get('category')}) generó el "
        f"hallazgo {f.get('finding_id')} con severidad {f.get('severity')}"
        + (f" y score {score} (banda {band})" if score is not None else "")
        + f" sobre {f.get('total_events_matched')} evento(s)"
        + f"{_fmt_range(f.get('time_range') or {})}.",
        evidence,
    ))

    statements = f.get("statements") or {}
    for label in ("hecho", "inferencia", "hipotesis"):
        label_out = {"hecho": "Hecho", "inferencia": "Inferencia", "hipotesis": "Hipótesis"}[label]
        for item in statements.get(label) or []:
            if isinstance(item, str) and item.strip():
                paragraphs.append(_paragraph(label_out, item, evidence))

    ents = f.get("entities") or {}
    paragraphs.append(_paragraph(
        "Hecho",
        f"Entidades observadas en la evidencia: usuarios {_fmt_list(ents.get('users') or [])}; "
        f"hosts {_fmt_list(ents.get('hosts') or [])}; IPs de origen {_fmt_list(ents.get('source_ips') or [])}; "
        f"destinos {_fmt_list(ents.get('destinations') or [])}.",
        evidence,
    ))

    absorbed = f.get("absorbed_detail")
    if absorbed:
        paragraphs.append(_paragraph(
            "Hecho",
            "Este hallazgo absorbe hallazgos de reglas de menor nivel (ver detalle en "
            "'absorbed_detail'); el detalle por víctima queda registrado sin duplicar hallazgos.",
            evidence,
        ))

    mitre = f.get("mitre") or []
    if mitre:
        paragraphs.append(_paragraph(
            "Hecho",
            f"Técnicas MITRE citadas por la regla: {', '.join(str(m) for m in mitre)}.",
            evidence,
        ))
    return paragraphs


def incident_paragraphs(
    inc: Dict[str, Any],
    findings_by_id: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    member_ids = list(inc.get("findings") or [])
    citations: List[str] = []
    for fid in member_ids:
        f = findings_by_id.get(fid)
        if f:
            citations.extend(_evidence_of(f))
    citations = citations[:_MAX_CITATIONS] or None
    paragraphs: List[Dict[str, Any]] = []

    grouping = inc.get("grouping") or {}
    paragraphs.append(_paragraph(
        "Hecho",
        f"El incidente {inc.get('incident_id')} (banda {inc.get('band')}, score {inc.get('score')}) "
        f"agrupa {len(member_ids)} hallazgo(s)"
        f"{_fmt_range(inc.get('time_range') or {})}. Justificación de agrupación: "
        f"{grouping.get('justification', '')}",
        citations,
    ))

    phases = inc.get("kill_chain_phases") or []
    mitre = inc.get("mitre") or []
    if phases or mitre:
        paragraphs.append(_paragraph(
            "Hecho",
            "Fases de kill chain observadas: " + (_fmt_list([str(p) for p in phases], 8))
            + ". Técnicas MITRE observadas: " + (_fmt_list([str(m) for m in mitre], 10) + "."),
            citations,
        ))

    timeline = inc.get("timeline") or []
    if timeline:
        steps = []
        for step in timeline[:8]:
            ids = ", ".join(step.get("evidence_log_ids") or [])
            steps.append(
                f"{step.get('time') or 'sin hora'}: {step.get('finding_id')} ({step.get('rule_id')}, "
                f"{step.get('severity')}, score {step.get('score')}) evidencia [{ids}]"
            )
        paragraphs.append(_paragraph(
            "Hecho",
            "Secuencia temporal de los hallazgos del incidente: " + "; ".join(steps) + ".",
            citations,
        ))

    iocs = inc.get("iocs") or {}
    if iocs:
        parts = [f"{kind}: {_fmt_list([str(v) for v in vals], 5)}" for kind, vals in iocs.items() if vals]
        paragraphs.append(_paragraph(
            "Hecho",
            "IoCs extraídos únicamente de los eventos citados como evidencia: " + "; ".join(parts) + ".",
            citations,
        ))
    else:
        paragraphs.append(_paragraph(
            "Hecho",
            "No se observaron IoCs en la evidencia citada del incidente.",
            citations,
        ))

    alias_notes = grouping.get("alias_notes") or []
    if alias_notes:
        paragraphs.append(_paragraph(
            "Inferencia",
            "Notas de alias en la agrupación: " + " ".join(str(n) for n in alias_notes) + ".",
            citations,
        ))
    return paragraphs


def build_template_sections(result, findings: List[Dict[str, Any]], incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Secciones deterministas completas: resumen + hallazgos + incidentes."""
    findings_by_id = {f.get("finding_id"): f for f in findings}
    sections: List[Dict[str, Any]] = [
        {
            "section_id": "resumen_ejecutivo",
            "title": "Resumen ejecutivo",
            "paragraphs": executive_summary_paragraphs(result, findings, incidents),
        }
    ]
    for f in findings:
        sections.append({
            "section_id": f"hallazgo:{f.get('finding_id')}",
            "title": f"Hallazgo {f.get('finding_id')} — {f.get('rule_id')} ({f.get('rule_name')})",
            "paragraphs": finding_paragraphs(f),
        })
    for inc in incidents:
        sections.append({
            "section_id": f"incidente:{inc.get('incident_id')}",
            "title": f"Incidente {inc.get('incident_id')} — {inc.get('title')}",
            "paragraphs": incident_paragraphs(inc, findings_by_id),
        })
    return sections
