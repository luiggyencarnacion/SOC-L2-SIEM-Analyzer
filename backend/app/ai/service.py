# ai/service.py - Orquestador de redaccion (fase E).
# Flujo: contexto estructurado -> (plantillas | proveedor IA) -> validador
# anti-alucinacion -> fallback a plantillas por parrafo descartado.
# La IA solo redacta; la deteccion y las cifras son siempre del motor determinista.
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from app.ai import providers as providers_mod
from app.ai.base import AIProviderError
from app.ai.masking import build_mask, mask_payload, unmask_text
from app.ai.settings import (
    AiSettings,
    effective_provider,
    load_ai_settings,
    uses_masking,
)
from app.ai.validator import SectionContext, context_from_pool, validate_paragraphs
from app.reporting.templates import (
    NO_EVIDENCE_PHRASE,
    build_template_sections,
)

_NO_EVIDENCE_SENTINELS = ("EVT-", "ROW-", "F-", "I-")

SYSTEM_PROMPT = (
    "Eres un analista SOC de nivel 2. Redactas parrafos de informe a partir EXCLUSIVAMENTE de los "
    "hallazgos estructurados y la evidencia que se te entrega. No detectas ni inventas: no puedes "
    "anadir entidades, cifras, horas ni eventos que no esten en los datos entregados. Cada parrafo "
    "debe citar al menos un Log_ID de la evidencia de su propia seccion. Si un hallazgo no tiene "
    "evidencia, escribe exactamente: \"" + NO_EVIDENCE_PHRASE + "\". Etiqueta cada parrafo como "
    "'Hecho', 'Inferencia' o 'Hipotesis'. Responde SOLO con JSON valido de la forma "
    '{"paragraphs": [{"section": "<id de seccion>", "label": "Hecho", "text": "...", '
    '"citations": ["<Log_ID>"]}]}. Sin texto fuera del JSON.'
)


def _clip(value: Any, max_chars: int = 200) -> str:
    s = str(value or "")
    return s if len(s) <= max_chars else s[: max_chars - 3] + "..."


def _collect_case_entities(events: List[Dict[str, Any]]) -> Set[str]:
    out: Set[str] = set()
    for ev in events:
        for key in ("user_raw", "host_raw", "source_ip", "destination_raw",
                    "destination_host", "destination_ip"):
            v = ev.get(key)
            if v not in (None, ""):
                out.add(str(v).casefold())
    return out


def _evidence_rows(events: List[Dict[str, Any]], log_ids: List[str]) -> List[Dict[str, Any]]:
    wanted = set(log_ids)
    rows = []
    for ev in events:
        lid = str(ev.get("log_id") or "")
        if lid in wanted:
            rows.append({
                "log_id": lid,
                "timestamp": ev.get("timestamp_parsed") or ev.get("timestamp_raw"),
                "usuario": ev.get("user_raw"),
                "host": ev.get("host_raw"),
                "ip_origen": ev.get("source_ip"),
                "evento": ev.get("event_code"),
                "resultado": ev.get("result_norm"),
                "mensaje": _clip(ev.get("event_description") or ev.get("raw")),
                "comando": _clip(ev.get("process_command_line")),
                "url": _clip(ev.get("url_path")),
                "share": ev.get("share"),
                "ruta": _clip(ev.get("file_path")),
                "bytes_out": ev.get("bytes_out"),
                "logon_type": ev.get("logon_type"),
            })
    return rows


def _extra_entities(values: Any, out: Set[str]) -> None:
    if isinstance(values, (list, tuple)):
        for v in values:
            _extra_entities(v, out)
    elif values not in (None, ""):
        s = str(values)
        if not any(s.startswith(p) for p in _NO_EVIDENCE_SENTINELS):
            out.add(s)


def _contexts_and_payload(
    result,
    findings: List[Dict[str, Any]],
    incidents: List[Dict[str, Any]],
) -> Dict[str, SectionContext]:
    """Construye el contexto de validacion por seccion y el payload para el LLM."""
    events = result.events
    session_log_ids = {str(e.get("log_id")) for e in events if e.get("log_id")}
    case_entities = _collect_case_entities(events)
    findings_by_id = {f.get("finding_id"): f for f in findings}
    contexts: Dict[str, SectionContext] = {}
    payload_sections: List[Dict[str, Any]] = []

    # --- resumen ejecutivo: puede citar la evidencia de cualquier hallazgo ---
    all_evidence_ids: List[str] = []
    for f in findings:
        all_evidence_ids.extend(f.get("evidence_log_ids") or [])
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev_counts[f.get("severity")] = sev_counts.get(f.get("severity"), 0) + 1
    resumen_numbers = [
        len(events), len(findings), len(incidents),
        sum(1 for e in events if e.get("timestamp_parsed")),
    ] + [v for v in sev_counts.values()]
    resumen_rows = _evidence_rows(events, all_evidence_ids)
    ctx = context_from_pool(
        "resumen_ejecutivo", resumen_rows, session_log_ids, case_entities, resumen_numbers
    )
    # El resumen puede citar hallazgos por su id y las reglas por su identificador.
    for f in findings:
        ctx.allowed_entities.add(str(f.get("finding_id")).casefold())
        ctx.allowed_entities.add(str(f.get("rule_id")).casefold())
    contexts["resumen_ejecutivo"] = ctx
    payload_sections.append({
        "section": "resumen_ejecutivo",
        "tipo": "resumen",
        "eventos_analizados": len(events),
        "total_hallazgos": len(findings),
        "hallazgos_por_severidad": sev_counts,
        "incidentes": [
            {"incident_id": i.get("incident_id"), "banda": i.get("band"), "score": i.get("score")}
            for i in incidents
        ],
    })

    # --- hallazgos ---
    for f in findings:
        section = f"hallazgo:{f.get('finding_id')}"
        rows = _evidence_rows(events, f.get("evidence_log_ids") or [])
        derived = [
            int(f.get("score") or 0),
            int(f.get("total_events_matched") or 0),
            int(f.get("total_evidence") or 0),
        ]
        ctx = context_from_pool(section, rows, session_log_ids, case_entities, derived)
        ctx.allowed_entities.add(str(f.get("rule_id")).casefold())
        ctx.allowed_entities.add(str(f.get("finding_id")).casefold())
        _extra_entities(f.get("mitre"), ctx.allowed_entities)
        contexts[section] = ctx
        payload_sections.append({
            "section": section,
            "tipo": "hallazgo",
            "regla": f.get("rule_id"),
            "nombre_regla": f.get("rule_name"),
            "severidad": f.get("severity"),
            "score": f.get("score"),
            "banda": f.get("band"),
            "mitre": f.get("mitre"),
            "afirmaciones": f.get("statements") or {},
            "entidades": f.get("entities") or {},
            "evidencia": rows,
        })

    # --- incidentes ---
    for inc in incidents:
        section = f"incidente:{inc.get('incident_id')}"
        member_ids = list(inc.get("findings") or [])
        ev_ids: List[str] = []
        for fid in member_ids:
            f = findings_by_id.get(fid)
            if f:
                ev_ids.extend(f.get("evidence_log_ids") or [])
        rows = _evidence_rows(events, ev_ids)
        derived = [
            int(inc.get("score") or 0),
            int(inc.get("max_finding_score") or 0),
            len(member_ids),
            len(ev_ids),
        ]
        ctx = context_from_pool(section, rows, session_log_ids, case_entities, derived)
        ctx.allowed_entities.add(str(inc.get("incident_id")).casefold())
        for fid in member_ids:
            ctx.allowed_entities.add(str(fid).casefold())
            mf = findings_by_id.get(fid)
            if mf:
                ctx.allowed_entities.add(str(mf.get("rule_id")).casefold())
        contexts[section] = ctx
        payload_sections.append({
            "section": section,
            "tipo": "incidente",
            "titulo": inc.get("title"),
            "banda": inc.get("band"),
            "score": inc.get("score"),
            "fases_kill_chain": inc.get("kill_chain_phases"),
            "mitre": inc.get("mitre"),
            "hallazgos": member_ids,
            "iocs": inc.get("iocs") or {},
            "justificacion_agrupacion": (inc.get("grouping") or {}).get("justification"),
            "evidencia": rows,
        })

    return contexts, {"secciones": payload_sections}


def _mask_groups(contexts: Dict[str, SectionContext], payload: Dict[str, Any]) -> Dict[str, List[str]]:
    """Grupos de entidades a enmascarar, deducidas del contexto y del payload."""
    groups: Dict[str, List[str]] = {"user": [], "host": [], "ip": [], "destination": [], "value": []}
    seen = set()

    def _add(kind: str, value: Any) -> None:
        s = str(value or "")
        if s and s not in seen and not any(s.startswith(p) for p in _NO_EVIDENCE_SENTINELS):
            seen.add(s)
            groups[kind].append(s)

    for section in payload.get("secciones", []):
        for row in section.get("evidencia") or []:
            _add("user", row.get("usuario"))
            _add("host", row.get("host"))
            _add("ip", row.get("ip_origen"))
            _add("value", row.get("url"))
            _add("value", row.get("share"))
            _add("value", row.get("ruta"))
        for ent in (section.get("entidades") or {}).items():
            kind = {"users": "user", "hosts": "host", "source_ips": "ip", "destinations": "destination"}.get(ent[0], "value")
            for v in ent[1] or []:
                _add(kind, v)
    return {k: v for k, v in groups.items() if v}


def generate_narrative(
    result,
    *,
    provider_override: Optional[str] = None,
    transport=None,
    masking_override: Optional[bool] = None,
) -> Dict[str, Any]:
    """Genera la redaccion de secciones a partir del analisis ya determinista.

    provider_override/transport existen para tests (sin llamadas reales).
    """
    settings: AiSettings = load_ai_settings()
    provider = provider_override or effective_provider(settings)
    findings: List[Dict[str, Any]] = list((result.detection or {}).get("findings", []))
    incidents: List[Dict[str, Any]] = list((result.correlation or {}).get("incidents", []))
    template_sections = build_template_sections(result, findings, incidents)

    ai_state: Dict[str, Any] = {
        "used": False,
        "provider": provider,
        "model": settings.model if provider != "none" else "",
        "masking": False,
        "accepted_paragraphs": 0,
        "rejected": [],
        "error": None,
    }

    if provider == "none":
        return _assemble(result, template_sections, ai_state, mode="plantillas")

    contexts, payload = _contexts_and_payload(result, findings, incidents)
    masking = uses_masking(provider) if masking_override is None else masking_override
    mapping: Dict[str, str] = {}
    if masking:
        mapping = build_mask(_mask_groups(contexts, payload))
        payload = mask_payload(payload, mapping)
        ai_state["masking"] = bool(mapping)

    user_prompt = (
        "Datos estructurados del analisis (unica fuente permitida). Redacta un parrafo por cada "
        "seccion indicada:\n" + json.dumps(payload, ensure_ascii=False, default=str)
    )

    adapter = None
    try:
        adapter = providers_mod.get_adapter(provider, settings, transport)
        raw = adapter.generate(SYSTEM_PROMPT, user_prompt)
    except AIProviderError as exc:
        ai_state["error"] = str(exc)
        return _assemble(result, template_sections, ai_state, mode="plantillas")
    finally:
        if adapter is not None:
            try:
                adapter.close()
            except Exception:
                pass

    unmask = (lambda t: unmask_text(t, mapping)) if mapping else None
    accepted, rejected = validate_paragraphs(raw, contexts, unmask=unmask)
    ai_state["used"] = True
    ai_state["accepted_paragraphs"] = len(accepted)
    ai_state["rejected"] = rejected

    accepted_by_section: Dict[str, List[Dict[str, Any]]] = {}
    for p in accepted:
        accepted_by_section.setdefault(p["section"], []).append(p)

    for section in template_sections:
        sid = section["section_id"]
        ai_paragraphs = accepted_by_section.get(sid) or []
        if ai_paragraphs:
            # La IA completa la seccion; la plantilla queda como respaldo implicito
            # en los datos estructurados (no se mezclan textos de ambas fuentes).
            section["paragraphs"] = ai_paragraphs
    return _assemble(result, template_sections, ai_state, mode="ia")


def _assemble(result, sections: List[Dict[str, Any]], ai_state: Dict[str, Any], mode: str) -> Dict[str, Any]:
    total_paragraphs = sum(len(s["paragraphs"]) for s in sections)
    return {
        "session_id": getattr(result, "session_id", None),
        "sheet": result.sheet,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "total_sections": len(sections),
        "total_paragraphs": total_paragraphs,
        "sections": sections,
        "ai_state": ai_state,
    }
