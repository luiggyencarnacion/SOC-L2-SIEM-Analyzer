# reporting/report.py - Informe técnico completo (fase F + pulido de presentación).
# Todo el contenido se construye de forma determinista a partir de:
#   - los eventos normalizados (evidencia con Log_ID y texto literal),
#   - los hallazgos del motor (detection) y los incidentes (correlation),
#   - la calidad de datos y la cobertura de reglas,
#   - la redacción validada por IA (narrative) si existe: solo sustituye párrafos.
# Regla de oro: si una sección no tiene datos, frase exacta obligatoria.
# Nota de bandas: el informe usa SIEMPRE la banda final (score tras factores y
# bonus), no la severidad base de la regla; la diferencia se explica en el informe.
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from app.reporting.charts import BAND_COLORS, BAND_ORDER, donut_svg, incident_timeline_svg, mitre_bars_svg
from app.reporting.templates import NO_EVIDENCE_PHRASE

SEVERITY_ORDER = ["Crítico", "Alto", "Medio", "Bajo"]

BAND_LABELS: Dict[str, str] = {b: b for b in BAND_ORDER}

# Etiquetas en español de los tipos de IoC (claves internas del correlador).
IOC_LABELS: Dict[str, str] = {
    "ips": "IPs públicas",
    "hosts": "Hosts",
    "urls": "URLs",
    "cuentas": "Cuentas",
    "shares": "Shares SMB",
    "rutas": "Rutas/archivos",
    "servicios_tareas": "Servicios/Tareas",
    "hashes": "Hashes",
}

# Estados de cobertura en español (antes se mostraban en inglés).
COVERAGE_STATUS_ES: Dict[str, str] = {
    "executed": "Ejecutada",
    "executed_no_findings": "Ejecutada sin hallazgos",
    "insufficient_data": "Datos insuficientes",
    "skipped_missing_fields": "Omitida por campos faltantes",
    "skipped_disabled": "Omitida (deshabilitada)",
    "error": "Error",
}

# Plan de acción por categoría: contenido de las fases Investigar / Contener / Remediar.
_ACTION_LIBRARY: Dict[str, Dict[str, str]] = {
    "autenticación": {
        "investigar": "Revisar la evidencia citada (Log_ID) y confirmar con el propietario de las cuentas si la actividad es legítima.",
        "contener": "Bloquear la IP de origen en el perímetro y restablecer las credenciales de las cuentas afectadas.",
        "remediar": "Habilitar MFA para las cuentas implicadas y revisar políticas de bloqueo por intentos fallidos.",
    },
    "privilegios": {
        "investigar": "Identificar quién autorizó el cambio de privilegios y qué cuentas resultaron afectadas.",
        "contener": "Revocar los privilegios no justificados y supervisar de cerca las cuentas involucradas.",
        "remediar": "Auditar la pertenencia a grupos privilegiados y reforzar el proceso de aprobación de altas.",
    },
    "ejecución": {
        "investigar": "Recopilar el proceso, su línea de comandos y el binario implicado; consultar su reputación.",
        "contener": "Aislar el host afectado y poner en cuarentena el binario o script detectado.",
        "remediar": "Limpiar o reinstalar el equipo y buscar el mismo indicador en el resto del parque.",
    },
    "persistencia": {
        "investigar": "Documentar la tarea/servicio observado, su origen de instalación y el proceso que lo creó.",
        "contener": "Deshabilitar la tarea o servicio y bloquear el binario asociado.",
        "remediar": "Eliminar el mecanismo de persistencia y comprobar que no existe en otros equipos.",
    },
    "movimiento lateral": {
        "investigar": "Revisar los accesos remotos y compartidos citados en la evidencia y su legitimidad.",
        "contener": "Aislar los hosts implicados y rotar las credenciales que pudieran estar comprometidas.",
        "remediar": "Restringir el uso de cuentas de servicio interactivas y revisar permisos de compartidos.",
    },
    "exfiltración": {
        "investigar": "Cuantificar el volumen transferido al destino externo y identificar el origen de los datos.",
        "contener": "Bloquear el destino externo en el firewall/proxy y suspender la cuenta implicada si procede.",
        "remediar": "Evaluar el impacto de la fuga con el área propietaria de los datos y notificar si aplica.",
    },
    "web": {
        "investigar": "Revisar las peticiones citadas, el código expuesto y el proceso hijo del servidor web.",
        "contener": "Bloquear la IP de origen y deshabilitar la aplicación o ruta afectada.",
        "remediar": "Corregir la vulnerabilidad, reconstruir el servidor desde imagen limpia y revisar registros.",
    },
}
_DEFAULT_ACTION = {
    "investigar": "Investigar la evidencia citada (Log_ID) y confirmar si la actividad es legítima.",
    "contener": "Aislar los activos implicados y bloquear los indicadores observados.",
    "remediar": "Eliminar la causa raíz y verificar que la actividad no se repite.",
}
_ACTION_OWNER: Dict[str, str] = {
    "autenticación": "SOC L2 / IT Identidad",
    "privilegios": "IT Identidad",
    "ejecución": "IT Sistemas",
    "persistencia": "IT Sistemas",
    "movimiento lateral": "SOC L2 / IT Sistemas",
    "exfiltración": "Redes / IT",
    "web": "Equipo de la aplicación",
}
_DEFAULT_OWNER = "SOC L2"
# Plazo sugerido según la banda final del incidente.
_ACTION_SLA: Dict[str, str] = {
    "Crítico": "24 h",
    "Alto": "72 h",
    "Medio": "7 días",
    "Bajo": "30 días",
}

_MAX_TEXT_CELL = 300


def _now_iso() -> str:
    return datetime.now().isoformat(sep=" ", timespec="minutes")


def _fmt_date_long(iso: str) -> str:
    """Fecha legible dd/mm/aaaa hh:mm a partir de un ISO o cadena."""
    try:
        dt = datetime.fromisoformat(str(iso))
        return dt.strftime("%d/%m/%Y %H:%M")
    except ValueError:
        return str(iso or "")


def _fmt_short_time(value: Any) -> str:
    """Hora corta dd/mm hh:mm:ss para tablas."""
    s = str(value or "")
    try:
        dt = datetime.fromisoformat(s)
        return dt.strftime("%d/%m %H:%M:%S")
    except ValueError:
        return s


def _clip(value: Any, max_chars: int = _MAX_TEXT_CELL) -> str:
    s = "" if value is None else str(value)
    return s if len(s) <= max_chars else s[: max_chars - 3] + "..."


def _clean(value: Any) -> str:
    s = "" if value is None else str(value).strip()
    return "" if s == "-" else s


def _fmt_list(values: List[str], max_items: int = 5) -> str:
    values = [v for v in values if _clean(v)]
    if not values:
        return "ninguna"
    shown = values[:max_items]
    txt = ", ".join(shown)
    if len(values) > max_items:
        txt += f" y {len(values) - max_items} más"
    return txt


def _table(
    table_id: str,
    title: str,
    columns: List[Tuple[str, str]],
    rows: List[Dict[str, Any]],
    widths: Optional[List[int]] = None,
    mono_cols: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "table_id": table_id,
        "title": title,
        "columns": [{"key": k, "label": lbl} for k, lbl in columns],
        "rows": rows,
        "widths": widths,
        "mono_cols": mono_cols or [],
    }


def _para(label: str, text: str, citations: Optional[List[str]] = None, source: str = "plantilla") -> Dict[str, Any]:
    return {"label": label, "text": text, "citations": list(citations or [])[:8], "source": source}


def _section(
    number: str,
    section_id: str,
    title: str,
    kind: str,
    paragraphs: List[Dict[str, Any]],
    tables: Optional[List[Dict[str, Any]]] = None,
    editable: bool = True,
    parent: Optional[str] = None,
    level: int = 1,
    break_before: bool = False,
    landscape: bool = False,
    cards: Optional[List[Dict[str, Any]]] = None,
    charts: Optional[List[Dict[str, Any]]] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "number": number,
        "section_id": section_id,
        "title": title,
        "kind": kind,
        "paragraphs": paragraphs,
        "tables": tables or [],
        "editable": editable,
        "edited": False,
        "edited_at": None,
        "parent": parent,
        "level": level,
        "break_before": break_before,
        "landscape": landscape,
        "cards": cards or [],
        "charts": charts or [],
        "meta": meta or {},
    }


def _anchor(section_id: str) -> str:
    """Id HTML estable para el índice clicable del PDF."""
    return "sec-" + str(section_id).replace(":", "-")


def _sev_rank(band: Any) -> int:
    try:
        return SEVERITY_ORDER.index(band)
    except ValueError:
        return 99


def _band_of(f: Dict[str, Any]) -> str:
    """Banda FINAL del hallazgo (score tras factores); si no hay scoring, la base."""
    return str(f.get("band") or f.get("severity") or "Sin banda")


def _evidence_ids(f: Dict[str, Any], limit: int = 6) -> List[str]:
    return [str(x) for x in (f.get("evidence_log_ids") or [])][:limit]


def _literal_row_text(ev: Dict[str, Any], columns: List[str]) -> str:
    """Texto literal de la fila cruda: columnas y valores tal como están en el log."""
    fields = (ev.get("raw") or {}).get("fields") or []
    parts = []
    for i, val in enumerate(fields):
        if val in (None, ""):
            continue
        col = columns[i] if i < len(columns) else f"col{i + 1}"
        parts.append(f"{col}={_clip(val, 120)}")
    return " | ".join(parts) if parts else "(fila sin valores legibles)"


def _mitre_pairs(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counts: Dict[str, int] = {}
    for f in findings:
        for m in f.get("mitre") or []:
            counts[str(m)] = counts.get(str(m), 0) + 1
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [{"technique": t, "count": c} for t, c in ordered]


def _get_meta(result) -> Dict[str, str]:
    meta = getattr(result, "report_meta", None) or {}
    return {
        "cliente": _clean(meta.get("cliente")) or "(cliente por completar)",
        "analista": _clean(meta.get("analista")) or "(analista por completar)",
    }


# ------------------------- plantillas de redacción base -------------------------

def _resumen_cards(result, findings: List[Dict[str, Any]], incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    assets: set = set()
    users: set = set()
    for f in findings:
        ents = f.get("entities") or {}
        assets.update(_clean(h) for h in (ents.get("hosts") or []))
        users.update(_clean(u) for u in (ents.get("users") or []))
    assets.discard(""); users.discard("")
    return [
        {"label": "Eventos analizados", "value": len(result.events), "hint": result.sheet},
        {"label": "Hallazgos", "value": len(findings), "hint": "motor determinista"},
        {"label": "Incidentes", "value": len(incidents), "hint": "correlacionados"},
        {"label": "Activos afectados", "value": len(assets) + len(users), "hint": f"{len(assets)} hosts · {len(users)} cuentas"},
    ]


def _incident_blurb(inc: Dict[str, Any], findings_by_id: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """3 frases deterministas sobre lo que pasó, con citas de evidencia del incidente."""
    members = [findings_by_id.get(fid) for fid in (inc.get("findings") or [])]
    members = [m for m in members if m]
    top = sorted(members, key=lambda f: -(f.get("score") or 0))[:2]
    rules = _fmt_list([str(f.get("rule_name") or f.get("rule_id")) for f in top], 2)
    ents = inc.get("assets") or {}
    host = _fmt_list([_clean(h) for h in (ents.get("hosts") or [])], 2)
    users = _fmt_list([_clean(u) for u in (ents.get("users") or [])], 2)
    tr = inc.get("time_range") or {}
    inicio = _fmt_short_time(tr.get("start"))
    frases = [
        f"{inc.get('incident_id')} — {inc.get('title')}: banda {inc.get('band')}.",
        f"Qué pasó: {rules} implicando {host or 'hosts sin identificar'}"
        + (f" con las cuentas {users}" if users and users != "ninguna" else "")
        + (f" entre {inicio} y {_fmt_short_time(tr.get('end'))}" if inicio else "") + ".",
        f"Alcance: {len(members)} hallazgo(s) en fases {_fmt_list([str(p) for p in (inc.get('kill_chain_phases') or [])], 4)}.",
    ]
    citas: List[str] = []
    for f in sorted(members, key=lambda x: -(x.get("score") or 0)):
        citas.extend(_evidence_ids(f, 2))
    # Dedup preservando orden.
    seen: set = set()
    citas = [c for c in citas if not (c in seen or seen.add(c))][:3]
    return _para("Hecho", " ".join(frases), citas or None)


def _finding_meta(f: Dict[str, Any]) -> Dict[str, Any]:
    ents = f.get("entities") or {}
    return {
        "banda": _band_of(f),
        "score": f.get("score"),
        "regla": f.get("rule_id"),
        "regla_nombre": f.get("rule_name"),
        "mitre": [str(m) for m in (f.get("mitre") or [])],
        "usuarios": [_clean(u) for u in (ents.get("users") or [])][:5],
        "hosts": [_clean(h) for h in (ents.get("hosts") or [])][:5],
        "ips": [_clean(i) for i in (ents.get("source_ips") or [])][:5],
        "log_ids": _evidence_ids(f, 8),
        "total_evidencia": f.get("total_evidence"),
        "override": (f.get("override") or {}).get("classification") or "",
    }


def _incident_meta(inc: Dict[str, Any]) -> Dict[str, Any]:
    assets = inc.get("assets") or {}
    return {
        "banda": inc.get("band"),
        "score": inc.get("score"),
        "fases": [str(p) for p in (inc.get("kill_chain_phases") or [])],
        "hosts": [_clean(h) for h in (assets.get("hosts") or [])][:6],
        "usuarios": [_clean(u) for u in (assets.get("users") or [])][:6],
        "hallazgos": len(inc.get("findings") or []),
    }


# ------------------------- construcción del informe -------------------------

def _base_sections(result) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = [dict(f) for f in (result.detection or {}).get("findings", [])]
    incidents: List[Dict[str, Any]] = [dict(i) for i in (result.correlation or {}).get("incidents", [])]
    overrides = getattr(result, "overrides", {}) or {}
    for f in findings:
        ov = overrides.get(f"finding:{f.get('finding_id')}")
        if ov:
            f["override"] = ov
    for inc in incidents:
        ov = overrides.get(f"incident:{inc.get('incident_id')}")
        if ov:
            inc["override"] = ov
    findings_by_id = {f.get("finding_id"): f for f in findings}

    # Párrafos: solo se heredan los validados por IA (fase E); el resto sale de
    # las plantillas base de este módulo (la IA no detecta, solo redacta).
    ia_paragraphs: Dict[str, List[Dict[str, Any]]] = {}
    for s in (result.narrative or {}).get("sections") or []:
        ia = [dict(p) for p in (s.get("paragraphs") or []) if p.get("source") == "ia_validada"]
        if ia:
            ia_paragraphs[s.get("section_id")] = ia

    def _paras(section_id: str, base: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return ia_paragraphs.get(section_id) or base

    sections: List[Dict[str, Any]] = []
    chapter = [0]

    def _next_chapter() -> str:
        chapter[0] += 1
        return str(chapter[0])

    # 1. Resumen ejecutivo (una página): tarjetas, dona y lo esencial por incidente.
    band_counts: Dict[str, int] = {}
    for f in findings:
        band_counts[_band_of(f)] = band_counts.get(_band_of(f), 0) + 1
    blurbs = [_incident_blurb(inc, findings_by_id) for inc in incidents] or (
        [_para("Hecho", NO_EVIDENCE_PHRASE)]
    )
    # Resumen a 1 pagina: la redaccion IA/plantilla del capitulo (si existe) va
    # de intro y los blurbs por incidente SIEMPRE estan presente (requisito A2).
    resumenes = _paras("resumen_ejecutivo", [])
    sections.append(_section(
        _next_chapter(), "resumen_ejecutivo", "Resumen ejecutivo", "resumen",
        (resumenes + blurbs) or [_para("Hecho", NO_EVIDENCE_PHRASE)],
        cards=_resumen_cards(result, findings, incidents),
        charts=[donut_svg(band_counts)],
        break_before=True,
    ))

    # 2. Metodología, alcance y cobertura.
    sections.append(_section(
        _next_chapter(), "metodologia", "Metodología, alcance y cobertura", "texto",
        _paras("metodologia", _metodologia_paragraphs(result)),
        break_before=True,
    ))

    # 3. Tabla resumen de hallazgos.
    sections.append(_section(
        _next_chapter(), "tabla_hallazgos", "Tabla resumen de hallazgos", "tabla",
        _paras("tabla_hallazgos", (
            [_para("Hecho", NO_EVIDENCE_PHRASE)] if not findings else [
                _para("Hecho", f"La tabla resume los {len(findings)} hallazgo(s) generados por el motor "
                               "determinista, ordenados por banda final y score. La banda final puede "
                               "diferir de la severidad base de la regla: el score suma factores "
                               "(tope +30) y el incidente añade bonus por fases (tope +15)."),
            ]
        )),
        tables=[_findings_summary_table(findings)],
    ))

    # 4. Hallazgos (capítulo) con cada hallazgo como tarjeta/subpunto.
    sections.append(_section(
        _next_chapter(), "hallazgos", "Hallazgos", "contenedor",
        _paras("hallazgos", (
            [_para("Hecho", NO_EVIDENCE_PHRASE)] if not findings else [
                _para("Hecho", f"A continuación se detallan los {len(findings)} hallazgo(s) del motor "
                               "determinista, ordenados temporalmente. Cada tarjeta indica la banda "
                               "final, la regla que la generó, las técnicas MITRE y la evidencia."),
            ]
        )),
        charts=[mitre_bars_svg(_mitre_pairs(findings))] if findings else [],
        editable=False,
        break_before=True,
    ))
    for i, f in enumerate(findings, start=1):
        sid = f"hallazgo:{f.get('finding_id')}"
        title = f"{f.get('rule_name')} ({f.get('rule_id')})"
        sections.append(_section(
            f"{chapter[0]}.{i}", sid, title, "hallazgo",
            _paras(sid, _finding_paragraphs(f)),
            parent="hallazgos", level=2,
            meta=_finding_meta(f),
        ))

    # 5. Incidentes (capítulo) con cronología por incidente.
    sections.append(_section(
        _next_chapter(), "incidentes", "Incidentes", "contenedor",
        _paras("incidentes", (
            [_para("Hecho", NO_EVIDENCE_PHRASE)] if not incidents else [
                _para("Hecho", f"Se presentan los {len(incidents)} incidente(s) resultantes de la "
                               "correlación por identidad fuerte compartida dentro de la ventana "
                               "temporal; compartir host nunca agrupa por sí solo."),
            ]
        )),
        editable=False,
    ))
    for i, inc in enumerate(incidents, start=1):
        sid = f"incidente:{inc.get('incident_id')}"
        sections.append(_section(
            f"{chapter[0]}.{i}", sid, str(inc.get("title")), "incidente",
            _paras(sid, _incident_paragraphs(inc, findings_by_id)),
            parent="incidentes", level=2,
            charts=[incident_timeline_svg(inc)],
            meta=_incident_meta(inc),
        ))

    # 6. Criticidad y justificación (siempre banda final).
    sections.append(_section(
        _next_chapter(), "criticidad", "Criticidad y justificación", "tabla",
        _paras("criticidad", [_para(
            "Hecho",
            "Las bandas de esta sección son la banda FINAL: score del hallazgo = base según severidad "
            "de la regla + factores (tope +30); el score del incidente = máximo de sus hallazgos + "
            "5 por cada fase de kill chain observada más allá de la primera (tope +15). La severidad "
            "declarada por el SIEM no influye en el puntaje.",
        )]),
        tables=_criticality_tables(findings, incidents),
    ))

    # 7. Impacto observado.
    sections.append(_section(
        _next_chapter(), "impacto", "Impacto observado", "texto",
        _paras("impacto", _impact_paragraphs(result, findings)),
    ))

    # 8. Plan de acción (tabla por incidente).
    sections.append(_section(
        _next_chapter(), "plan_accion", "Plan de acción", "plan",
        _paras("plan_accion", (
            [_para("Hecho", NO_EVIDENCE_PHRASE)] if not incidents else [
                _para("Hecho", "Plan por incidente con las fases Investigar, Contener y Remediar; la "
                               "prioridad y el plazo se derivan de la banda final del incidente y las "
                               "acciones de las categorías de sus hallazgos. Responsable y plazo son "
                               "sugerencias editables por el analista."),
            ]
        )),
        tables=_action_plan_tables(incidents, findings_by_id),
    ))

    # 9. IoCs.
    ioc_table = _iocs_table(incidents)
    sections.append(_section(
        _next_chapter(), "iocs", "Indicadores de compromiso (IoCs)", "tabla",
        _paras("iocs", (
            [_para("Hecho", "IoCs extraídos únicamente de los eventos citados como evidencia; los "
                            "hosts no se mezclan con dominios y se excluyen valores vacíos.")] if ioc_table["rows"] else [
                _para("Hecho", NO_EVIDENCE_PHRASE),
            ]
        )),
        tables=[ioc_table] if ioc_table["rows"] else [],
    ))

    # 10. Recomendaciones generales.
    sections.append(_section(
        _next_chapter(), "recomendaciones", "Recomendaciones generales", "texto",
        _paras("recomendaciones", _recommendation_paragraphs(result)),
    ))

    # 11. Limitaciones.
    sections.append(_section(
        _next_chapter(), "limitaciones", "Limitaciones", "texto",
        _paras("limitaciones", _limitation_paragraphs(result)),
    ))

    # Anexos (salto de página antes del primero; evidencias en horizontal).
    annex_letters = {
        "anexo_calidad": "A",
        "anexo_cobertura": "B",
        "anexo_evidencias": "C",
        "anexo_alias": "D",
    }
    for sid, title, builder in (
        ("anexo_calidad", "Anexo A: calidad de datos", _annex_quality_tables),
        ("anexo_cobertura", "Anexo B: cobertura de reglas", _annex_coverage_tables),
        ("anexo_evidencias", "Anexo C: evidencias completas (Log_ID)", _annex_evidence_table),
        ("anexo_alias", "Anexo D: alias de identidades", _annex_alias_tables),
    ):
        letter = annex_letters[sid]
        if sid == "anexo_evidencias":
            tables = [builder(result, findings)] if findings else []
            landscape = bool(tables)
        else:
            tables = builder(result)
            landscape = False
        first_annex = sid == "anexo_calidad"
        if tables or sid != "anexo_evidencias":
            sections.append(_section(
                letter, sid, title, "anexo",
                [_para("Hecho", "Datos generados directamente del análisis; sin interpretación adicional.")],
                tables=tables,
                landscape=landscape,
                break_before=first_annex,
            ))
        else:
            sections.append(_section(letter, sid, title, "anexo", [_para("Hecho", NO_EVIDENCE_PHRASE)],
                                     break_before=first_annex))

    return sections


# ------------------------- plantillas por sección -------------------------

def _metodologia_paragraphs(result) -> List[Dict[str, Any]]:
    cov = (result.detection or {}).get("summary") or {}
    corr = (result.correlation or {}).get("summary") or {}
    ts = (result.quality or {}).get("timestamp") or {}
    return [
        _para("Hecho",
              "Metodología: ingesta del .xlsx (sin macros ni fórmulas), normalización de campos "
              "universales, detección por reglas deterministas (YAML + motor), puntuación por "
              "factores con tope +30 y correlación por identidad fuerte con ventana temporal. "
              "La IA no participa en la detección; solo puede redactar párrafos que después se "
              "validan contra la evidencia."),
        _para("Hecho",
              f"Alcance: {len(result.events)} eventos de la hoja '{result.sheet}'. El motor ejecutó "
              f"{cov.get('rules_executed')} de {cov.get('total_rules')} reglas "
              f"({cov.get('rules_skipped_disabled')} deshabilitadas, "
              f"{cov.get('rules_skipped_missing_fields')} omitidas por campos faltantes, "
              f"{cov.get('rules_insufficient_data')} con datos insuficientes, "
              f"{cov.get('rules_error')} con error) y generó {cov.get('total_findings')} hallazgo(s) "
              f"agrupados en {corr.get('total_incidents')} incidente(s)."),
        _para("Hecho",
              f"Calidad temporal: {ts.get('wall', 0)} eventos con hora de pared y {ts.get('offset', 0)} "
              f"con zona horaria; {ts.get('invalid', 0)} inválidos y {ts.get('missing', 0)} sin hora. "
              "Las comparaciones temporales usan la hora tal como aparece en el log (política de "
              "timestamps del análisis, sin conversión de zona)."),
    ]


def _findings_summary_table(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    ordered = sorted(findings, key=lambda f: (_sev_rank(_band_of(f)), -(f.get("score") or 0), str(f.get("finding_id"))))
    rows = []
    for f in ordered:
        rows.append({
            "finding_id": f.get("finding_id"),
            "rule_id": f.get("rule_id"),
            "band": _band_of(f),
            "score": f.get("score"),
            "events": f.get("total_events_matched"),
            "mitre": ", ".join(str(m) for m in (f.get("mitre") or [])),
        })
    cols = [
        ("finding_id", "ID"), ("rule_id", "Regla"), ("band", "Banda"),
        ("score", "Score"), ("events", "Eventos"), ("mitre", "MITRE"),
    ]
    return _table("tabla_hallazgos", "Resumen de hallazgos", cols, rows, widths=[10, 18, 14, 10, 12, 36])


def _finding_paragraphs(f: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Tarjeta de hallazgo: qué ocurrió, por qué importa e hipótesis (citas incluidas)."""
    evidence = [str(x) for x in (f.get("evidence_log_ids") or [])]
    paragraphs: List[Dict[str, Any]] = []
    if not evidence:
        paragraphs.append(_para("Hecho", NO_EVIDENCE_PHRASE))
        return paragraphs
    hechos = [s for s in (f.get("statements") or {}).get("hecho", []) if isinstance(s, str) and s.strip()]
    if hechos:
        paragraphs.append(_para("Hecho", " ".join(hechos[:2]), evidence[:4]))
    else:
        paragraphs.append(_para(
            "Hecho",
            f"La regla {f.get('rule_id')} ({f.get('rule_name')}) coincidió en {f.get('total_events_matched')} "
            f"evento(s) entre {_fmt_short_time((f.get('time_range') or {}).get('start'))} y "
            f"{_fmt_short_time((f.get('time_range') or {}).get('end'))}.",
            evidence[:4],
        ))
    why = str(f.get("rationale") or "").strip()
    inferencias = [s for s in (f.get("statements") or {}).get("inferencia", []) if isinstance(s, str) and s.strip()]
    if inferencias:
        paragraphs.append(_para("Inferencia", ("Por qué importa: " + inferencias[0]), evidence[:4]))
    elif why:
        paragraphs.append(_para("Inferencia", f"Por qué importa: {why}", evidence[:4]))
    absorbed = f.get("absorbed_detail")
    if absorbed:
        victims = []
        try:
            for _k, v in (absorbed.items() if isinstance(absorbed, dict) else []):
                if isinstance(v, dict):
                    victims.extend(v.get("victimas") or v.get("usuarios") or [])
        except Exception:
            victims = []
        if victims:
            paragraphs.append(_para(
                "Hecho",
                f"Este hallazgo incluye {len(victims)} detección(es) de menor nivel absorbidas "
                f"(desglose por víctima disponible en la aplicación): {_fmt_list([str(v) for v in victims][:5], 5)}.",
                evidence[:3],
            ))
    hipotesis = [s for s in (f.get("statements") or {}).get("hipotesis", []) if isinstance(s, str) and s.strip()]
    for h in hipotesis[:2]:
        paragraphs.append(_para("Hipótesis", h, evidence[:3]))
    return paragraphs


def _incident_paragraphs(inc: Dict[str, Any], findings_by_id: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Tarjeta de incidente: resumen, justificación de agrupación y IoCs observados."""
    member_ids = list(inc.get("findings") or [])
    citations: List[str] = []
    for fid in member_ids:
        f = findings_by_id.get(fid)
        if f:
            citations.extend(_evidence_ids(f, 2))
    seen: set = set()
    citations = [c for c in citations if not (c in seen or seen.add(c))][:8] or None
    grouping = inc.get("grouping") or {}
    tr = inc.get("time_range") or {}
    paragraphs: List[Dict[str, Any]] = [
        _para(
            "Hecho",
            f"El incidente agrupa {len(member_ids)} hallazgo(s) entre {_fmt_short_time(tr.get('start'))} y "
            f"{_fmt_short_time(tr.get('end'))}. Fases de kill chain observadas: "
            f"{_fmt_list([str(p) for p in (inc.get('kill_chain_phases') or [])], 6)}.",
            citations,
        ),
        _para("Hecho", f"Justificación de la agrupación: {grouping.get('justification', '')}", citations),
    ]
    iocs = inc.get("iocs") or {}
    parts = [f"{IOC_LABELS.get(k, k)}: {_fmt_list([_clean(v) for v in vals], 4)}" for k, vals in iocs.items() if vals]
    if parts:
        paragraphs.append(_para("Hecho", "Indicadores observados en la evidencia: " + "; ".join(parts) + ".", citations))
    for nota in (grouping.get("alias_notes") or [])[:2]:
        paragraphs.append(_para("Inferencia", str(nota), citations))
    ov = inc.get("override") or {}
    if ov:
        paragraphs.append(_para("Hecho", f"Clasificación manual del analista: {ov.get('classification')} — {ov.get('reason')}"))
    return paragraphs


def _criticality_tables(findings: List[Dict[str, Any]], incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows_f = []
    for f in sorted(findings, key=lambda x: -(x.get("score") or 0)):
        ov = f.get("override") or {}
        factores = "; ".join(
            f"{fa.get('factor')}(+{fa.get('points')})" for fa in (f.get("factors_applied") or [])
        )
        rows_f.append({
            "target": f.get("finding_id"),
            "band": _band_of(f),
            "score": f.get("score"),
            "factors": _clip(factores, 120) or "sin factores",
            "override": (f"{ov.get('classification')}" if ov else ""),
        })
    rows_i = []
    for inc in sorted(incidents, key=lambda x: -(x.get("score") or 0)):
        ov = inc.get("override") or {}
        rows_i.append({
            "target": inc.get("incident_id"),
            "title": _clip(str(inc.get("title")), 60),
            "band": inc.get("band"),
            "score": inc.get("score"),
            "phases": ", ".join(str(p) for p in (inc.get("kill_chain_phases") or [])),
            "override": (f"{ov.get('classification')}" if ov else ""),
        })
    return [
        _table("criticidad_hallazgos", "Criticidad de hallazgos (banda final)",
               [("target", "ID"), ("band", "Banda"), ("score", "Score"), ("factors", "Factores"), ("override", "Override")],
               rows_f, widths=[10, 12, 10, 50, 18]),
        _table("criticidad_incidentes", "Criticidad de incidentes",
               [("target", "ID"), ("title", "Título"), ("band", "Banda"), ("score", "Score"), ("phases", "Fases"), ("override", "Override")],
               rows_i, widths=[8, 40, 12, 10, 22, 8]),
    ]


def _fmt_bytes(n: int) -> str:
    """Bytes legibles en español: separador de miles punto y MB como unidad."""
    miles = f"{n:,}".replace(",", ".")
    mb = n / (1024 * 1024)
    if mb >= 1:
        mb_txt = f"{mb:.1f}".replace(".", ",")
        return f"{miles} bytes (≈{mb_txt} MB)"
    return f"{miles} bytes"


def _impact_paragraphs(result, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Impacto observado: solo agregados factuales derivados de la evidencia."""
    if not findings:
        return [_para("Hecho", NO_EVIDENCE_PHRASE)]
    hosts: set = set()
    users: set = set()
    ips: set = set()
    destinos: set = set()
    for f in findings:
        ents = f.get("entities") or {}
        hosts.update(_clean(h) for h in (ents.get("hosts") or []))
        users.update(_clean(u) for u in (ents.get("users") or []))
        ips.update(_clean(i) for i in (ents.get("source_ips") or []))
        destinos.update(_clean(d) for d in (ents.get("destinations") or []))
    # Citas deduplicadas preservando orden (un mismo Log_ID puede citarse en varios hallazgos).
    seen: set = set()
    citas = [lid for lid in (lid for f in findings for lid in _evidence_ids(f, 2)) if not (lid in seen or seen.add(lid))][:8]
    paragraphs = [
        _para("Hecho",
              f"Activos y cuentas implicados en los hallazgos: hosts {_fmt_list(sorted(hosts))}; "
              f"cuentas {_fmt_list(sorted(users))}; IPs de origen {_fmt_list(sorted(ips))}; "
              f"destinos {_fmt_list(sorted(destinos))}.",
              citas or None),
    ]
    by_log_id = {str(e.get("log_id")): e for e in result.events if e.get("log_id")}
    total_bytes = 0
    for f in findings:
        for lid in f.get("evidence_log_ids") or []:
            ev = by_log_id.get(str(lid))
            if ev and isinstance(ev.get("bytes_out"), (int, float)):
                total_bytes += int(ev["bytes_out"])
    if total_bytes > 0:
        paragraphs.append(_para("Hecho", f"Volumen de salida observado en la evidencia citada (bytes_out): {_fmt_bytes(total_bytes)}."))
    cats = sorted({_clean(f.get("category")) for f in findings if _clean(f.get("category"))})
    paragraphs.append(_para("Hecho", "Categorías de hallazgos observadas: " + _fmt_list(cats, 10) + "."))
    return paragraphs


def _action_plan_tables(incidents: List[Dict[str, Any]], findings_by_id: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Plan de acción: una tabla por incidente con Investigar/Contener/Remediar."""
    tables: List[Dict[str, Any]] = []
    for inc in incidents:
        members = [findings_by_id.get(fid) for fid in (inc.get("findings") or [])]
        members = [m for m in members if m]
        cats = sorted({_clean(m.get("category")) for m in members if _clean(m.get("category"))})
        band = str(inc.get("band") or "Medio")
        sla = _ACTION_SLA.get(band, "7 días")
        rows = []
        for fase in ("Investigar", "Contener", "Remediar"):
            acciones = []
            owners = set()
            for cat in cats or ["otros"]:
                lib = _ACTION_LIBRARY.get(cat.lower(), _DEFAULT_ACTION)
                acciones.append(lib.get(fase.lower(), _DEFAULT_ACTION[fase.lower()]))
                owners.add(_ACTION_OWNER.get(cat.lower(), _DEFAULT_OWNER))
            rows.append({
                "fase": fase,
                "accion": " ".join(acciones),
                "prioridad": band,
                "owner": "; ".join(sorted(owners)),
                "sla": sla,
            })
        tables.append(_table(
            f"plan_{inc.get('incident_id')}",
            f"{inc.get('incident_id')} — {_clip(str(inc.get('title')), 70)} (banda {band})",
            [("fase", "Fase"), ("accion", "Acción"), ("prioridad", "Prioridad"),
             ("owner", "Responsable sugerido"), ("sla", "Plazo sugerido")],
            rows, widths=[12, 46, 12, 18, 12],
        ))
    return tables


def _iocs_table(incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
    rows = []
    for inc in incidents:
        for kind, values in (inc.get("iocs") or {}).items():
            for v in values or []:
                v = _clean(v)
                if not v:
                    continue
                rows.append({"tipo": IOC_LABELS.get(kind, kind), "valor": _clip(v, 160),
                             "incident": inc.get("incident_id")})
    rows.sort(key=lambda r: (r["tipo"], r["valor"]))
    cols = [("tipo", "Tipo"), ("valor", "Valor"), ("incident", "Incidente")]
    return _table("iocs", "Indicadores de compromiso extraídos de la evidencia citada", cols, rows,
                  widths=[22, 62, 16])


def _recommendation_paragraphs(result) -> List[Dict[str, Any]]:
    """Recomendaciones generales derivadas de la calidad de datos y la cobertura."""
    q = result.quality or {}
    ts = q.get("timestamp") or {}
    cov = (result.detection or {}).get("summary") or {}
    paragraphs: List[Dict[str, Any]] = []
    if int(ts.get("invalid") or 0) or int(ts.get("missing") or 0):
        paragraphs.append(_para("Hecho",
                                f"Mejorar el registro de horas: {ts.get('invalid')} inválidas y {ts.get('missing')} "
                                "eventos sin hora reducen la fiabilidad de la correlación temporal."))
    if int(cov.get("rules_skipped_missing_fields") or 0):
        paragraphs.append(_para("Hecho",
                                f"{cov.get('rules_skipped_missing_fields')} regla(s) no pudieron ejecutarse por "
                                "campos faltantes en el export; ampliar las columnas del export del SIEM "
                                "aumentaría la cobertura."))
    if int(cov.get("rules_insufficient_data") or 0):
        paragraphs.append(_para("Hecho",
                                f"{cov.get('rules_insufficient_data')} regla(s) quedaron sin datos suficientes "
                                "(requieren línea base histórica que este análisis no tiene); considerar "
                                "incorporar una línea base en futuras iteraciones."))
    dups = q.get("duplicate_log_ids") or []
    if dups:
        paragraphs.append(_para("Hecho",
                                f"Existen {len(dups)} Log_ID duplicados en el export; revisar la generación de "
                                "identificadores en el SIEM para evitar ambigüedad en la evidencia."))
    if not paragraphs:
        paragraphs.append(_para("Hecho",
                                "No se identificaron déficits de calidad ni de cobertura que exijan acciones "
                                "prioritarias; mantener la configuración actual de export del SIEM."))
    return paragraphs


def _limitation_paragraphs(result) -> List[Dict[str, Any]]:
    """Limitaciones: solo lo observable en los datos."""
    cov = (result.detection or {}).get("summary") or {}
    ts = (result.quality or {}).get("timestamp") or {}
    paragraphs: List[Dict[str, Any]] = [
        _para("Hecho",
              "El análisis se limita a las filas del archivo cargado; no hay acceso al SIEM en vivo ni a "
              "línea base histórica, por lo que las reglas que la requieren quedan sin evaluar (ver "
              "Anexo B)."),
    ]
    if int(ts.get("wall") or 0) and not int(ts.get("offset") or 0):
        paragraphs.append(_para("Hecho",
                                "Las horas del archivo son de pared sin zona horaria declarada; las "
                                "comparaciones temporales usan esa hora tal cual, según la política de "
                                "timestamps del análisis."))
    skipped = int(cov.get("rules_skipped_missing_fields") or 0) + int(cov.get("rules_insufficient_data") or 0)
    if skipped:
        paragraphs.append(_para("Hecho",
                                f"{skipped} regla(s) quedaron fuera del análisis (campos faltantes o datos "
                                "insuficientes); la cobertura completa figura en el Anexo B."))
    return paragraphs


# ------------------------- anexos -------------------------

def _annex_quality_tables(result) -> List[Dict[str, Any]]:
    q = result.quality or {}
    ts = q.get("timestamp") or {}
    quality_rows = [
        {"metric": "Filas totales", "value": q.get("total_rows")},
        {"metric": "Horas válidas (pared)", "value": ts.get("wall")},
        {"metric": "Horas con zona horaria", "value": ts.get("offset")},
        {"metric": "Horas inválidas", "value": ts.get("invalid")},
        {"metric": "Eventos sin hora", "value": ts.get("missing")},
        {"metric": "Log_ID duplicados", "value": len(q.get("duplicate_log_ids") or [])},
        {"metric": "Columnas con tipos mezclados", "value": ", ".join(q.get("mixed_type_columns") or []) or "ninguna"},
    ]
    cols_col = [
        ("column", "Columna"), ("populated", "Con valor"), ("nulls", "Nulos"),
        ("null_percent", "% nulos"), ("distinct", "Distintos"),
    ]
    rows = [{k: c.get(k) for k, _ in cols_col} for c in (q.get("columns") or [])]
    return [
        _table("anexo_calidad_resumen", "Resumen de calidad de datos",
               [("metric", "Métrica"), ("value", "Valor")], quality_rows, widths=[55, 45]),
        _table("anexo_calidad_columnas", "Nulos por columna", cols_col, rows),
    ]


def _annex_coverage_tables(result) -> List[Dict[str, Any]]:
    coverage = (result.detection or {}).get("coverage") or []
    if not coverage:
        return []
    rows = [
        {
            "rule_id": c.get("rule_id"),
            "status": COVERAGE_STATUS_ES.get(str(c.get("status")), str(c.get("status"))),
            "reason": _clip(_clean(c.get("reason")), 140) or "—",
            "findings": c.get("findings"),
        }
        for c in coverage
    ]
    cols = [("rule_id", "Regla"), ("status", "Estado"), ("reason", "Motivo"), ("findings", "Hallazgos")]
    return [_table("anexo_cobertura", "Cobertura del motor de detección", cols, rows, widths=[16, 26, 46, 12])]


def _annex_evidence_table(result, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Evidencias deduplicadas: una fila por Log_ID, texto literal monoespaciado."""
    cited: set = set()
    for f in findings:
        cited.update(str(x) for x in (f.get("evidence_log_ids") or []))
    by_log_id = {str(e.get("log_id")): e for e in result.events if e.get("log_id")}
    rows = []
    for lid in sorted(cited):
        ev = by_log_id.get(lid)
        if ev is None:
            rows.append({"log_id": lid, "time": None, "host": None, "user": None,
                         "src": None, "event": None, "result": None,
                         "literal": "(Log_ID citado no encontrado en los eventos cargados)"})
            continue
        rows.append({
            "log_id": lid,
            "time": _fmt_short_time(ev.get("timestamp_parsed") or ev.get("timestamp_raw")),
            "host": _clip(ev.get("host_raw"), 40),
            "user": _clip(ev.get("user_raw"), 40),
            "src": _clean(ev.get("source_ip")),
            "event": _clean(ev.get("event_code")),
            "result": _clean(ev.get("result_norm")),
            "literal": _literal_row_text(ev, result.columns),
        })
    cols = [
        ("log_id", "Log_ID"), ("time", "Hora"), ("literal", "Texto literal de la fila (todas las columnas del log)"),
    ]
    return _table("anexo_evidencias", "Evidencias citadas por los hallazgos (una fila por Log_ID)",
                  cols, rows, widths=[9, 12, 79], mono_cols=["log_id", "literal"])


def _annex_alias_tables(result) -> List[Dict[str, Any]]:
    aliases = (result.quality or {}).get("aliases") or {}
    rows = []
    for kind in ("hosts", "users"):
        for rel in aliases.get(kind) or []:
            members = [str(m) for m in (rel.get("members") or []) if str(m).strip() not in ("", "-")]
            key = _clean(rel.get("key"))
            # Identidad vacia (sin clave ni valores): no aporta contenido.
            if not key and not members:
                continue
            rows.append({
                "kind": "Hosts" if kind == "hosts" else "Cuentas",
                "status": rel.get("status"),
                "key": key,
                "members": _clip(", ".join(members), 140),
                "merged": "sí" if rel.get("merged") else "no",
                "rationale": _clip(rel.get("rationale"), 140),
            })
    if not rows:
        return []
    cols = [
        ("kind", "Tipo"), ("status", "Estado"), ("key", "Clave canónica"),
        ("members", "Valores observados"), ("merged", "Fusionada"), ("rationale", "Justificación"),
    ]
    return [_table("anexo_alias", "Relaciones de alias entre identidades", cols, rows)]


# ------------------------- informe completo + edición -------------------------

def build_report(result) -> Dict[str, Any]:
    """Informe completo con las ediciones del analista aplicadas."""
    sections = _base_sections(result)
    edits = getattr(result, "report_edits", {}) or {}
    for s in sections:
        edit = edits.get(s["section_id"])
        if edit:
            s["paragraphs"] = [dict(p) for p in edit.get("paragraphs") or []]
            s["edited"] = True
            s["edited_at"] = edit.get("edited_at")
    meta = _get_meta(result)
    return {
        "sheet": result.sheet,
        "file_name": _clean(getattr(result, "file_name", None)) or "",
        "generated_at": _now_iso(),
        "generated_at_human": _fmt_date_long(_now_iso()),
        "total_sections": len(sections),
        "sections": sections,
        "no_evidence_phrase": NO_EVIDENCE_PHRASE,
        "meta": meta,
        "band_colors": BAND_COLORS,
    }


# ------------------------- edición de secciones -------------------------

VALID_LABELS = ("Hecho", "Inferencia", "Hipótesis", "Hipotesis")
MAX_SECTION_CHARS = 20000
MAX_PARAGRAPHS = 50


def parse_section_text(text: str) -> List[Dict[str, Any]]:
    """Convierte el texto editado por el analista en párrafos etiquetados.

    Cada línea no vacía es un párrafo. Puede llevar el prefijo 'Hecho:', 'Inferencia:'
    o 'Hipótesis:' (tildes opcionales); sin prefijo se etiqueta como 'Hecho'.
    """
    paragraphs: List[Dict[str, Any]] = []
    for raw_line in (text or "").replace("\r\n", "\n").split("\n"):
        line = raw_line.strip()
        if not line:
            continue
        label = "Hecho"
        for lab in VALID_LABELS:
            prefix = f"{lab}:"
            if line.casefold().startswith(prefix.casefold()):
                label = "Hipótesis" if lab in ("Hipótesis", "Hipotesis") else lab
                line = line[len(prefix):].strip()
                break
        if not line:
            continue
        paragraphs.append(_para(label, line, source="manual"))
    return paragraphs


def apply_section_edit(result, section_id: str, text: str) -> Dict[str, Any]:
    """Guarda la edición del analista para una sección (sobre la base determinista)."""
    editable = {s["section_id"] for s in _base_sections(result) if s["editable"]}
    if section_id not in editable:
        known_all = {s["section_id"] for s in _base_sections(result)}
        if section_id in known_all:
            raise ValueError(f"La sección '{section_id}' es un contenedor genérico y no es editable.")
        raise KeyError(section_id)
    if len(text or "") > MAX_SECTION_CHARS:
        raise ValueError(f"La sección no puede superar {MAX_SECTION_CHARS} caracteres.")
    paragraphs = parse_section_text(text)
    if not paragraphs:
        raise ValueError("La edición no puede quedar vacía; usa 'regenerar' para restaurar la plantilla.")
    if len(paragraphs) > MAX_PARAGRAPHS:
        raise ValueError(f"La sección no puede tener más de {MAX_PARAGRAPHS} párrafos.")
    edit = {"section_id": section_id, "paragraphs": paragraphs, "edited_at": _now_iso()}
    result.report_edits[section_id] = edit
    return edit


def regenerate_section(result, section_id: str) -> Optional[Dict[str, Any]]:
    """Elimina la edición del analista: la sección vuelve a su contenido base."""
    editable = {s["section_id"] for s in _base_sections(result) if s["editable"]}
    if section_id not in editable:
        known_all = {s["section_id"] for s in _base_sections(result)}
        if section_id in known_all:
            raise ValueError(f"La sección '{section_id}' es un contenedor genérico y no es editable.")
        raise KeyError(section_id)
    result.report_edits.pop(section_id, None)
    for s in _base_sections(result):
        if s["section_id"] == section_id:
            return s
    return None


def set_report_meta(result, cliente: Optional[str] = None, analista: Optional[str] = None) -> Dict[str, str]:
    """Guarda los datos editables de la portada (cliente y analista) en la sesión."""
    meta = getattr(result, "report_meta", None) or {}
    if cliente is not None:
        meta["cliente"] = _clean(cliente)
    if analista is not None:
        meta["analista"] = _clean(analista)
    result.report_meta = meta
    return _get_meta(result)
