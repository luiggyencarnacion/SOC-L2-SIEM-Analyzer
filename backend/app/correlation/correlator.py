# correlation/correlator.py - Correlacion de hallazgos en incidentes (fase C, PLAN 6.4).
# Politicas del plan:
# - Nunca se agrupa solo por compartir host: la agrupacion exige una identidad fuerte
#   compartida (usuario, IP de origen o destino) ademas de proximidad temporal.
# - Ventana temporal configurable (90 min por defecto).
# - Relaciones cruzadas "mismo activo" para cadenas independientes que comparten host.
# - Fases kill chain solo si estan observadas; justificacion de agrupacion explicita.
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from app.correlation.loader import CorrelationConfig
from app.ingestion.normalize import normalize_key, validate_ip

# Tipos de entidad que SÍ agrupan con fuerza (PLAN 4.2: solo identidades exactas).
STRONG_KINDS = ("users", "source_ips", "destinations")
# Entidades debiles: nunca agrupan solas, solo generan relacion "mismo activo".
WEAK_KINDS = ("hosts", "shares")

_IOC_LIMIT = 50


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def finding_ranges(finding: Dict[str, Any]) -> Tuple[Optional[datetime], Optional[datetime]]:
    tr = finding.get("time_range") or {}
    return _parse_iso(tr.get("start")), _parse_iso(tr.get("end"))


def _canon(value: Any) -> str:
    """Clave canonica de entidad; para cuentas quita el dominio tipo DOMINIO\\user."""
    s = str(value or "").strip()
    if "\\" in s:
        s = s.split("\\")[-1]
    return normalize_key(s)


def entity_keys(finding: Dict[str, Any], cfg: CorrelationConfig) -> Dict[str, Dict[str, List[str]]]:
    """Entidades canonicas -> valores crudos que las produjeron.

    Devuelve {kind: {clave_canonica: [valores_crudos]}} para kinds fuertes y debiles.
    - Las reglas en cfg.non_linking_user_rules (objetivo masivo tipo spraying) no
      agrupan por usuario: el actor se vincula por su IP de origen.
    - Los destinos tipo share UNC son entidad debil (como el host): no agrupan.
    """
    out: Dict[str, Dict[str, List[str]]] = {}
    ents = finding.get("entities") or {}
    non_link_users = str(finding.get("rule_id") or "") in cfg.non_linking_user_rules
    mapping: Dict[str, List[Any]] = {
        "users": [] if non_link_users else (ents.get("users") or []),
        "source_ips": ents.get("source_ips") or [],
        "hosts": ents.get("hosts") or [],
        "destinations": [],
    }
    weak_shares: Dict[str, List[str]] = {}
    for v in ents.get("destinations") or []:
        raw = str(v).strip()
        if raw.startswith("\\\\"):
            # Share UNC: acceso a recurso compartido, entidad debil (PLAN 6.4).
            key = _canon(raw)
            if key and raw not in weak_shares.setdefault(key, []):
                weak_shares[key].append(raw)
        else:
            mapping["destinations"].append(v)
    for kind, values in mapping.items():
        by_key: Dict[str, List[str]] = {}
        for v in values:
            key = _canon(v)
            if not key:
                continue
            raw = str(v).strip()
            if raw not in by_key.setdefault(key, []):
                by_key[key].append(raw)
        out[kind] = by_key
    if weak_shares:
        out["shares"] = weak_shares
    return out


def _gap_seconds(a: Dict[str, Any], b: Dict[str, Any]) -> Optional[float]:
    """Distancia temporal entre rangos; None si alguno no tiene tiempos."""
    s1, e1 = finding_ranges(a)
    s2, e2 = finding_ranges(b)
    if not (s1 and e1 and s2 and e2):
        return None
    gap = max(s1, s2) - min(e1, e2)
    return max(0.0, gap.total_seconds())


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, i: int, j: int) -> None:
        ri, rj = self.find(i), self.find(j)
        if ri != rj:
            self.parent[ri] = rj


def _shared_entities(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, List[str]]:
    """Entidades fuertes/debiles compartidas entre dos hallazgos (por clave canonica)."""
    shared: Dict[str, List[str]] = {}
    for kind in STRONG_KINDS + WEAK_KINDS:
        keys_a, keys_b = a.get(kind, {}), b.get(kind, {})
        common = sorted(set(keys_a) & set(keys_b))
        if not common:
            continue
        raws: List[str] = []
        for k in common:
            for raw in (keys_a[k] + keys_b[k]):
                if raw not in raws:
                    raws.append(raw)
        shared[kind] = raws
    return shared


def _alias_note(shared: Dict[str, List[str]], kind: str) -> Optional[str]:
    """Si la entidad compartida viene de valores crudos distintos con la misma clave,
    la relacion se marca como 'relacion posible por alias (inferencia)' (PLAN 4.2)."""
    raws = shared.get(kind) or []
    if len({r.casefold() for r in raws}) > 1:
        return f"{kind}: {', '.join(sorted(set(raws)))}"
    return None


def _phase_for_rule(rule_id: str, cfg: CorrelationConfig) -> str:
    prefix = str(rule_id or "").split("-", 1)[0].upper()
    return cfg.kill_chain_prefixes.get(prefix, cfg.kill_chain_default)


def _sorted_phases(phases: Set[str], cfg: CorrelationConfig) -> List[str]:
    order = cfg.kill_chain_phase_order
    known = [p for p in order if p in phases]
    extra = sorted(p for p in phases if p not in order)
    return known + extra


def _incident_title(findings: List[Dict[str, Any]], cfg: "CorrelationConfig") -> str:
    """Titulo descriptivo y determinista: regla ancla (mayor score) + entidad principal.

    La frase por regla ancla sale de `incident_titles.phrases` (config.yaml);
    si no hay frase, se usa el nombre de la regla. La entidad principal es el
    host mas compartido; si no hay, la cuenta; si no, la IP de origen. Nunca
    inventa texto: solo frases de config y entidades observadas.
    """
    if not findings:
        return "Incidente sin hallazgos"
    anchor = max(findings, key=lambda f: (f.get("score") or 0))
    ents = anchor.get("entities") or {}
    hosts = [str(h) for h in (ents.get("hosts") or []) if str(h).strip() not in ("", "-")]
    users = [str(u) for u in (ents.get("users") or []) if str(u).strip() not in ("", "-")]
    ips = [str(i) for i in (ents.get("source_ips") or []) if str(i).strip() not in ("", "-")]
    principal = hosts[0] if hosts else (users[0] if users else (ips[0] if ips else ""))
    phrase = cfg.incident_title_phrases.get(str(anchor.get("rule_id") or ""), "")
    lead = phrase or str(anchor.get("rule_name") or anchor.get("rule_id") or "Hallazgo")
    title = f"{lead} en {principal}" if principal else lead
    return title[:90]


def _extract_iocs(evidence_events: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """IoCs deterministas desde los eventos de evidencia del incidente.

    Tipos correctos: los hosts no son dominios; se excluyen valores vacios o "-".
    """
    iocs: Dict[str, Set[str]] = {
        "ips": set(), "hosts": set(), "urls": set(),
        "rutas": set(), "shares": set(), "servicios_tareas": set(),
        "cuentas": set(), "hashes": set(),
    }

    def _clean(value: Any) -> Optional[str]:
        s = str(value or "").strip()
        if not s or s == "-":
            return None
        return s

    for ev in evidence_events:
        if not isinstance(ev, dict):
            continue
        ip, scope = validate_ip(ev.get("source_ip"))
        if ip and scope == "public":
            iocs["ips"].add(ip)
        dip, dscope = validate_ip(ev.get("destination_ip"))
        if dip and dscope == "public":
            iocs["ips"].add(dip)
        dst_host = _clean(ev.get("destination_host"))
        # Las rutas UNC de share (\\servidor\recurso) no son hosts: van a shares
        # con el valor completo; un hostname nunca se duplica como share.
        if dst_host and "\\" in dst_host:
            iocs["shares"].add(dst_host)
        elif dst_host:
            iocs["hosts"].add(dst_host)
        host_raw = _clean(ev.get("host_raw"))
        if host_raw:
            iocs["hosts"].add(host_raw)
        if ev.get("url_path"):
            base = _clean(dst_host or ev.get("destination_raw") or "")
            url = f"{base}{ev['url_path']}" if base else str(ev["url_path"])
            iocs["urls"].add(url)
        fp = _clean(ev.get("file_path"))
        if fp:
            iocs["rutas"].add(fp)
        share = _clean(ev.get("share"))
        if share:
            iocs["shares"].add(share)
        for field in ("task_name", "service_name"):
            v = _clean(ev.get(field))
            if v:
                iocs["servicios_tareas"].add(v)
        user = _clean(ev.get("user_raw"))
        if user:
            iocs["cuentas"].add(user)
        for field in ("sha256", "sha1", "md5", "hash"):
            v = _clean(ev.get(field))
            if v:
                iocs["hashes"].add(v)
    return {k: sorted(v)[:_IOC_LIMIT] for k, v in iocs.items()}


def build_incident(
    incident_id: str,
    members: List[Dict[str, Any]],
    evidence_events: List[Dict[str, Any]],
    cfg: CorrelationConfig,
    shared_summary: Dict[str, List[str]],
    max_gap_minutes: Optional[float],
    alias_notes: List[str],
) -> Dict[str, Any]:
    findings = sorted(
        members,
        key=lambda f: (f.get("time_range", {}).get("start") or "", f.get("finding_id", "")),
    )
    timeline = [
        {
            "time": f.get("time_range", {}).get("start"),
            "finding_id": f.get("finding_id"),
            "rule_id": f.get("rule_id"),
            "rule_name": f.get("rule_name"),
            "severity": f.get("severity"),
            "score": f.get("score"),
            "evidence_log_ids": list(f.get("evidence_log_ids") or []),
        }
        for f in findings
    ]

    # Entidades afectadas: union de las entidades de los hallazgos.
    assets: Dict[str, List[str]] = {"users": [], "hosts": [], "source_ips": [], "destinations": []}
    for f in members:
        for kind, values in (f.get("entities") or {}).items():
            if kind not in assets:
                continue
            for v in values:
                if v and v not in assets[kind]:
                    assets[kind].append(str(v))
    for kind in assets:
        assets[kind] = sorted(assets[kind])

    # Fases kill chain solo observadas (PLAN 6.4: no se inventan fases).
    phases = {_phase_for_rule(f.get("rule_id"), cfg) for f in members}
    phases_observed = _sorted_phases(phases, cfg)

    mitre: List[str] = []
    for f in findings:
        for t in f.get("mitre") or []:
            if t not in mitre:
                mitre.append(str(t))

    # PLAN 7: score_incidente = min(100, max(score) + bonus * (fases - 1)), tope de bonus.
    max_score = max(int(f.get("score") or 0) for f in members)
    bonus = min(cfg.incident_bonus_cap, cfg.incident_phase_bonus * max(0, len(phases_observed) - 1))
    score = max(0, min(100, max_score + bonus))

    from app.correlation.scoring import band_for

    grouping: Dict[str, Any] = {
        "shared_entities": shared_summary,
        "max_gap_minutes": round(max_gap_minutes, 1) if max_gap_minutes is not None else None,
        "window_minutes": cfg.window_minutes,
        "alias_notes": alias_notes,
        "justification": (
            "Hallazgos agrupados por entidades fuertes compartidas (usuario, IP de origen o destino) "
            "dentro de la ventana temporal configurada. Compartir host nunca agrupa por sí solo."
        ),
    }

    return {
        "incident_id": incident_id,
        "title": _incident_title(findings, cfg),
        "findings": [f.get("finding_id") for f in findings],
        "score": score,
        "band": band_for(score, cfg),
        "max_finding_score": max_score,
        "incident_bonus": bonus,
        "kill_chain_phases": phases_observed,
        "mitre": mitre,
        "timeline": timeline,
        "assets": assets,
        "iocs": _extract_iocs(evidence_events),
        "time_range": {
            "start": findings[0].get("time_range", {}).get("start"),
            "end": max(
                (f.get("time_range", {}).get("end") or "" for f in findings),
                default=None,
            ) or None,
        },
        "grouping": grouping,
        "override": None,
    }


def run_correlation(
    findings: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    cfg: CorrelationConfig,
) -> Dict[str, Any]:
    """Agrupa hallazgos ya puntuados en incidentes. Devuelve {incidents, relations, summary}."""
    if not findings:
        return {"incidents": [], "relations": [], "summary": {
            "total_incidents": 0, "incidents_by_band": {}, "window_minutes": cfg.window_minutes,
            "findings_assigned": 0, "total_findings": 0,
        }}

    window_seconds = cfg.window_minutes * 60
    ents = [entity_keys(f, cfg) for f in findings]
    by_log_id: Dict[str, Dict[str, Any]] = {}
    for ev in events:
        by_log_id[str(ev.get("log_id"))] = ev

    uf = _UnionFind(len(findings))
    alias_notes: Dict[int, List[str]] = {}
    gap_for_pair: Dict[Tuple[int, int], float] = {}

    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            shared = _shared_entities(ents[i], ents[j])
            strong = [k for k in STRONG_KINDS if shared.get(k)]
            if not strong:
                continue  # solo host compartido NUNCA agrupa (PLAN 6.4)
            gap = _gap_seconds(findings[i], findings[j])
            if gap is None or gap > window_seconds:
                continue  # fuera de la ventana temporal
            uf.union(i, j)
            gap_for_pair[(i, j)] = gap
            for kind in strong:
                note = _alias_note(shared, kind)
                if note:
                    alias_notes.setdefault(i, []).append(f"relación posible por alias (inferencia) — {note}")
                    alias_notes.setdefault(j, []).append(f"relación posible por alias (inferencia) — {note}")

    groups: Dict[int, List[int]] = {}
    for i in range(len(findings)):
        groups.setdefault(uf.find(i), []).append(i)

    # Ordenar grupos por tiempo de inicio del primer hallazgo.
    def group_start(idxs: List[int]) -> str:
        return min(
            (findings[i].get("time_range", {}).get("start") or "9999" for i in idxs),
            default="9999",
        )

    ordered = sorted(groups.values(), key=group_start)
    incidents: List[Dict[str, Any]] = []
    assigned: Set[int] = set()
    for n, idxs in enumerate(ordered, start=1):
        assigned.update(idxs)
        members = [findings[i] for i in idxs]
        # Resumen de entidades compartidas dentro del grupo (pares fusionados).
        shared_summary: Dict[str, List[str]] = {}
        max_gap: Optional[float] = None
        for a in range(len(idxs)):
            for b in range(a + 1, len(idxs)):
                pair = (min(idxs[a], idxs[b]), max(idxs[a], idxs[b]))
                shared = _shared_entities(ents[idxs[a]], ents[idxs[b]])
                for kind, raws in shared.items():
                    bucket = shared_summary.setdefault(kind, [])
                    for r in raws:
                        if r not in bucket:
                            bucket.append(r)
                gap = gap_for_pair.get(pair)
                if gap is not None and (max_gap is None or gap > max_gap):
                    max_gap = gap
        # Evidencia del incidente: eventos citados por sus hallazgos.
        evidence_ids: List[str] = []
        for f in members:
            for lid in f.get("evidence_log_ids") or []:
                if lid not in evidence_ids:
                    evidence_ids.append(str(lid))
        evidence_events = [by_log_id[lid] for lid in evidence_ids if lid in by_log_id]
        notes = sorted({n for i in idxs for n in alias_notes.get(i, [])})
        incidents.append(
            build_incident(
                incident_id=f"I-{n:03d}",
                members=members,
                evidence_events=evidence_events,
                cfg=cfg,
                shared_summary={k: sorted(v) for k, v in shared_summary.items()},
                max_gap_minutes=max_gap,
                alias_notes=notes,
            )
        )

    # Relaciones cruzadas: cadenas independientes que comparten host ("mismo activo").
    relations: List[Dict[str, Any]] = []
    for a in range(len(incidents)):
        for b in range(a + 1, len(incidents)):
            shared_hosts = sorted(set(incidents[a]["assets"]["hosts"]) & set(incidents[b]["assets"]["hosts"]))
            if not shared_hosts:
                continue
            relations.append({
                "incidents": [incidents[a]["incident_id"], incidents[b]["incident_id"]],
                "shared_hosts": shared_hosts,
                "conclusion": "mismo activo: cadenas independientes (no comparten cuenta, origen ni destino dentro de la ventana)",
            })

    by_band: Dict[str, int] = {}
    for inc in incidents:
        by_band[inc["band"]] = by_band.get(inc["band"], 0) + 1
    return {
        "incidents": incidents,
        "relations": relations,
        "summary": {
            "total_incidents": len(incidents),
            "incidents_by_band": by_band,
            "window_minutes": cfg.window_minutes,
            "findings_assigned": len(assigned),
            "total_findings": len(findings),
        },
    }
