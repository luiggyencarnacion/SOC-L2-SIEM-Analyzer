# ai/validator.py - Validador anti-alucinacion independiente del proveedor (fase E).
# PLAN seccion 10: el LLM debe citar Log_IDs; el backend valida existencia,
# pertenencia, cifras, IPs, usuarios, hosts y horas. Si un parrafo falla,
# se descarta y se usa la plantilla determinista; se registra el motivo.
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

VALID_LABELS = ("Hecho", "Inferencia", "Hipótesis")
_MAX_PARAGRAPH_CHARS = 5000

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
# Timestamps completos o parciales (fecha sola o fecha+hora).
_TS_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
# Identificadores tipo EVT-00123, F-001, I-002, AUTH-002, ROW-12.
_ID_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9_]*-[A-Za-z]{0,3}\d{1,6}\b")
_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_NUM_RE = re.compile(r"\b\d+\b")


@dataclass
class SectionContext:
    """Todo lo que un parrafo de la seccion tiene derecho a afirmar."""

    section_id: str
    allowed_log_ids: Set[str] = field(default_factory=set)      # pertenencia (evidencia)
    session_log_ids: Set[str] = field(default_factory=set)      # existencia (sesion)
    allowed_entities: Set[str] = field(default_factory=set)     # en minusculas
    case_entities: Set[str] = field(default_factory=set)        # en minusculas (todo el caso)
    allowed_numbers: Set[str] = field(default_factory=set)      # cifras verificables
    allowed_times: Set[str] = field(default_factory=set)        # "YYYY-MM-DD HH:MM"


def normalize_time(value: Any) -> Optional[str]:
    """Normaliza un timestamp a 'YYYY-MM-DD HH:MM' para comparar horas declaradas."""
    s = str(value or "")
    m = re.match(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})", s)
    if not m:
        return None
    return f"{m.group(1)} {m.group(2)}"


def _collect_entities(values: Any, out: Set[str]) -> None:
    if isinstance(values, (list, tuple, set)):
        for v in values:
            _collect_entities(v, out)
    elif values not in (None, ""):
        out.add(str(values).casefold())


def context_from_pool(section_id: str, events: List[Dict[str, Any]], session_log_ids: Set[str],
                      case_entities: Set[str], derived_numbers: Optional[List[int]] = None) -> SectionContext:
    """Construye el contexto de validacion desde las filas de evidencia de la seccion."""
    allowed_log_ids: Set[str] = set()
    allowed_entities: Set[str] = set()
    allowed_numbers: Set[str] = set()
    allowed_times: Set[str] = set()
    for ev in events:
        lid = str(ev.get("log_id") or "")
        if lid:
            allowed_log_ids.add(lid)
        t = normalize_time(ev.get("timestamp_parsed") or ev.get("timestamp_raw"))
        if t:
            allowed_times.add(t)
        # Cifras verificables: numeros presentes en los valores de la fila.
        for value in list(ev.values()):
            for num in _NUM_RE.findall(str(value or "")):
                allowed_numbers.add(num)
        # Entidades de la fila (usuarios, hosts, IPs, destinos).
        for key in ("user_raw", "host_raw", "source_ip", "destination_raw",
                    "destination_host", "destination_ip", "url_path", "share", "file_path"):
            _collect_entities(ev.get(key), allowed_entities)
    for n in derived_numbers or []:
        allowed_numbers.add(str(abs(n)))
    return SectionContext(
        section_id=section_id,
        allowed_log_ids=allowed_log_ids,
        session_log_ids=session_log_ids,
        allowed_entities=allowed_entities,
        case_entities=case_entities,
        allowed_numbers=allowed_numbers,
        allowed_times=allowed_times,
    )


def _strip_matches(text: str, regexes: List[re.Pattern]) -> str:
    out = text
    for rx in regexes:
        out = rx.sub(" ", out)
    return out


def _check_text_facts(text: str, ctx: SectionContext) -> Optional[str]:
    """Valida IPs, URLs, horas, entidades del caso y cifras del parrafo."""
    low = text.casefold()

    for ip in _IP_RE.findall(text):
        if ip.casefold() not in ctx.allowed_entities:
            return f"La IP '{ip}' no aparece en la evidencia de la seccion."

    for url in _URL_RE.findall(text):
        if url.casefold() not in ctx.allowed_entities:
            return "La respuesta menciona una URL que no aparece en la evidencia de la seccion."

    # Horas declaradas: cada timestamp mencionado debe existir en la evidencia.
    for ts in _TS_RE.findall(text):
        norm = normalize_time(ts)
        if norm and norm not in ctx.allowed_times:
            return f"La hora '{norm}' no corresponde a la evidencia de la seccion."

    # Entidades del caso (usuarios/hosts reales) fuera de la evidencia de la seccion.
    for entity in ctx.case_entities:
        if len(entity) >= 4 and entity in low and entity not in ctx.allowed_entities:
            return (
                f"La entidad '{entity}' existe en el caso pero no en la evidencia "
                f"de la seccion '{ctx.section_id}'."
            )

    # Identificadores tipo Log_ID/regla/hallazgo: solo los conocidos.
    stripped = _strip_matches(text, [_TS_RE, _IP_RE, _MITRE_RE, _ID_RE])
    ids_in_text = set(_ID_RE.findall(text)) | set(_MITRE_RE.findall(text))
    allowed_ids_ci = {x.casefold() for x in ctx.allowed_log_ids}
    for ident in ids_in_text:
        if ident.casefold() in allowed_ids_ci or ident.casefold() in ctx.allowed_entities:
            continue
        return f"El identificador '{ident}' no pertenece a la evidencia de la seccion."

    # Cifras: los conteos narrativos de 1-2 digitos se toleran; toda cifra de
    # 3+ digitos debe existir en la evidencia de la seccion (o ser un total
    # derivado del propio hallazgo/incidente, anadido por el servicio).
    for num in _NUM_RE.findall(stripped):
        if len(num) < 3:
            continue
        if num in ctx.allowed_numbers or num.lstrip("0") in ctx.allowed_numbers:
            continue
        return f"La cifra '{num}' no es verificable en la evidencia de la seccion."
    return None


def parse_llm_payload(raw: str) -> List[Dict[str, Any]]:
    """Extrae la lista de parrafos del JSON del LLM (tolera vallas ```json)."""
    text = str(raw or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text).strip()
    data = json.loads(text)
    paragraphs = data.get("paragraphs") if isinstance(data, dict) else None
    if not isinstance(paragraphs, list):
        raise ValueError("falta la lista 'paragraphs'")
    return [p for p in paragraphs if isinstance(p, dict)]


def validate_paragraphs(
    raw: str,
    contexts: Dict[str, SectionContext],
    unmask=None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Valida los parrafos devueltos por el LLM.

    Devuelve (aceptados, rechazados). Los aceptados salen con source 'ia_validada';
    cada rechazo lleva el motivo registrado (PLAN seccion 10).
    """
    accepted: List[Dict[str, Any]] = []
    rejected: List[Dict[str, Any]] = []

    try:
        items = parse_llm_payload(raw)
    except Exception as exc:  # JSON invalido: se descarta todo y se usa plantilla.
        reason = f"Respuesta no valida para el validador ({exc.__class__.__name__})."
        return [], [{"section": "*", "reason": reason}]

    for item in items:
        section = str(item.get("section") or "")
        text = str(item.get("text") or "").strip()
        if unmask is not None:
            text = unmask(text)
        label = str(item.get("label") or "Hecho").strip()
        citations = [str(c).strip() for c in (item.get("citations") or []) if str(c).strip()]

        base = {"section": section, "text_preview": text[:120]}
        ctx = contexts.get(section)
        if ctx is None:
            rejected.append({**base, "reason": f"Seccion desconocida: '{section}'."})
            continue
        if not text:
            rejected.append({**base, "reason": "Parrafo vacio."})
            continue
        if len(text) > _MAX_PARAGRAPH_CHARS:
            rejected.append({**base, "reason": "Parrafo demasiado largo."})
            continue
        if label not in VALID_LABELS:
            rejected.append({**base, "reason": f"Etiqueta '{label}' no permitida (usa Hecho, Inferencia o Hipótesis)."})
            continue
        if not citations:
            rejected.append({**base, "reason": "Sin citas Log_ID; el validador exige evidencia."})
            continue
        bad = None
        for cid in citations:
            if cid not in ctx.session_log_ids:
                bad = f"La cita '{cid}' no existe en los logs cargados."
                break
            if cid not in ctx.allowed_log_ids:
                bad = f"La cita '{cid}' esta fuera de la evidencia de la seccion '{ctx.section_id}'."
                break
        if bad:
            rejected.append({**base, "reason": bad})
            continue
        problem = _check_text_facts(text, ctx)
        if problem:
            rejected.append({**base, "reason": problem})
            continue
        accepted.append({
            "section": section,
            "label": "Hipótesis" if label == "Hipótesis" else label,
            "text": text,
            "citations": citations,
            "source": "ia_validada",
        })
    return accepted, rejected
