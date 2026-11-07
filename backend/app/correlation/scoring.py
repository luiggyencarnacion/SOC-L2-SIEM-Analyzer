# correlation/scoring.py - Scoring de hallazgos (fase C, PLAN seccion 7).
# Determinista: base por severidad (invariante de banda) + factores con tope.
# La severidad del SIEM no influye en el puntaje (PLAN 7.1).
from typing import Any, Dict, List

from app.correlation.loader import CorrelationConfig
from app.ingestion.normalize import normalize_key

# Factores que llegan ya etiquetados desde el motor de deteccion (finding['factors']).
_TAG_FACTORS = (
    "origen_publico",
    "acceso_a_datos_sensibles",
    "volumen_grande",
    "explotacion_web",
)


def band_for(score: int, cfg: CorrelationConfig) -> str:
    """Banda del score segun la config. Devuelve la primera banda que contiene el score."""
    for sev, (lo, hi) in cfg.bands.items():
        if lo <= score <= hi:
            return sev
    # Sin banda definida para el score (config incoherente): banda mas proxima.
    return min(cfg.bands.items(), key=lambda kv: abs(score - (kv[1][0] + kv[1][1]) / 2))[0]


def _matches_any_pattern(values: List[str], patterns: List[str]) -> bool:
    for v in values:
        needle = normalize_key(v)
        if not needle:
            continue
        for pat in patterns:
            if normalize_key(pat) and normalize_key(pat) in needle:
                return True
    return False


def compute_factors(finding: Dict[str, Any], cfg: CorrelationConfig) -> List[Dict[str, Any]]:
    """Deriva los factores aplicables al hallazgo, cada uno con sus puntos y motivo."""
    applied: List[Dict[str, Any]] = []
    tags = set(finding.get("factors") or [])
    entities = finding.get("entities") or {}
    rule_id = str(finding.get("rule_id") or "")
    category = str(finding.get("category") or "")

    def add(factor: str, detail: str) -> None:
        pts = cfg.factor_points.get(factor)
        if pts is None or pts <= 0:
            return
        applied.append({"factor": factor, "points": pts, "detail": detail})

    for tag in _TAG_FACTORS:
        if tag in tags:
            add(tag, "etiquetado por la regla de deteccion")

    hosts = sorted({normalize_key(h) for h in entities.get("hosts") or [] if h})
    users = sorted({normalize_key(u.split("\\")[-1]) for u in entities.get("users") or [] if u})

    if len(hosts) >= cfg.multi_host_min:
        add("multi_host", f"afecta a {len(hosts)} hosts distintos (>= {cfg.multi_host_min})")
    if category in cfg.persistence_categories:
        add("persistencia", "regla de categoria persistencia")
    if rule_id in cfg.evasion_rules:
        add("evasion", "regla de evasion codificada en la configuracion")
    if rule_id in cfg.repetition_rules:
        add("repeticion", "regla de repeticion/periodicidad codificada en la configuracion")
    if category in cfg.privileged_categories or _matches_any_pattern(users, cfg.privileged_user_patterns):
        add("contexto_privilegiado", "cuenta o contexto privilegiado segun patrones configurados")
    if _matches_any_pattern(hosts, cfg.critical_host_patterns):
        add("activo_critico", "host coincide con patrones de activo critico configurados")

    return applied


def score_finding(finding: Dict[str, Any], cfg: CorrelationConfig) -> Dict[str, Any]:
    """Anade score/band/factors_applied al hallazgo (in place) y lo devuelve."""
    severity = str(finding.get("severity") or "Bajo")
    base = cfg.base_scores.get(severity)
    if base is None:
        base = min(cfg.base_scores.values())
    factors = compute_factors(finding, cfg)
    raw_points = sum(f["points"] for f in factors)
    points = min(raw_points, cfg.factors_cap)
    score = max(0, min(100, base + points))
    finding["factors_applied"] = factors
    finding["factors_points"] = {"raw": raw_points, "applied": points, "cap": cfg.factors_cap}
    finding["base_score"] = base
    finding["score"] = score
    finding["band"] = band_for(score, cfg)
    return finding


def score_findings(findings: List[Dict[str, Any]], cfg: CorrelationConfig) -> List[Dict[str, Any]]:
    for f in findings:
        score_finding(f, cfg)
    return findings
