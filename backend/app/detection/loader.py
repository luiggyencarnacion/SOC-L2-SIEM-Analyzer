# detection/loader.py - Carga y validacion de las reglas desde YAML (PLAN seccion 6.1).
# Determisc: ninguna regla vive en codigo; el YAML define id, campos, parametros y MITRE.
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

import yaml

RULES_FILE = Path(__file__).resolve().parent / "rules" / "default_rules.yaml"

VALID_SEVERITIES = ("Bajo", "Medio", "Alto", "Crítico")
RULE_FIELDS = ("id", "name", "category", "description", "rationale", "base_severity")
VALID_COVERAGE_STATUS = (
    "executed",
    "executed_no_findings",
    "skipped_disabled",
    "skipped_missing_fields",
    "insufficient_data",
    "error",
)


class DetectionConfigError(ValueError):
    """Configuracion de reglas invalida (id duplicada, campo obligatorio, etc.)."""


@dataclass
class RuleConfig:
    id: str
    name: str
    category: str
    description: str
    rationale: str
    base_severity: str
    enabled: bool = True
    required_fields: List[str] = field(default_factory=list)
    optional_fields: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    mitre: List[str] = field(default_factory=list)
    evidence_limit: int = 10
    use_probable_aliases: bool = False


def _validate(rule: Dict[str, Any], index: int) -> RuleConfig:
    where = f"regla #{index + 1}"
    for f in RULE_FIELDS:
        if not rule.get(f):
            raise DetectionConfigError(f"{where}: falta el campo obligatorio '{f}'.")
    rid = str(rule["id"])
    if not rid or " " in rid:
        raise DetectionConfigError(f"{where}: 'id' invalido.")
    if rule["base_severity"] not in VALID_SEVERITIES:
        raise DetectionConfigError(f"{where} ({rid}): base_severity debe ser uno de {VALID_SEVERITIES}.")
    for list_field in ("required_fields", "optional_fields", "mitre"):
        val = rule.get(list_field, [])
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            raise DetectionConfigError(f"{where} ({rid}): '{list_field}' debe ser una lista de textos.")
    params = rule.get("parameters") or {}
    if not isinstance(params, dict):
        raise DetectionConfigError(f"{where} ({rid}): 'parameters' debe ser un objeto.")
    try:
        limit = int(rule.get("evidence_limit", 10))
    except (TypeError, ValueError):
        raise DetectionConfigError(f"{where} ({rid}): evidence_limit debe ser entero.")
    return RuleConfig(
        id=rid,
        name=str(rule["name"]),
        category=str(rule["category"]),
        description=str(rule["description"]),
        rationale=str(rule["rationale"]),
        base_severity=str(rule["base_severity"]),
        enabled=bool(rule.get("enabled", True)),
        required_fields=list(rule.get("required_fields", [])),
        optional_fields=list(rule.get("optional_fields", [])),
        parameters=dict(params),
        mitre=list(rule.get("mitre", [])),
        evidence_limit=limit,
        use_probable_aliases=bool(rule.get("use_probable_aliases", False)),
    )


def load_rules(path: Path | None = None) -> List[RuleConfig]:
    """Carga y valida las reglas. Falla rapido ante YAML corrupto o inconsistente."""
    file_path = path or RULES_FILE
    with open(file_path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise DetectionConfigError(f"{file_path.name}: estructura esperada {{ 'rules': [...] }}.")
    rules: List[RuleConfig] = []
    seen: set = set()
    for i, raw_rule in enumerate(data["rules"]):
        cfg = _validate(raw_rule, i)
        if cfg.id in seen:
            raise DetectionConfigError(f"{file_path.name}: id duplicada '{cfg.id}'.")
        seen.add(cfg.id)
        rules.append(cfg)
    if not rules:
        raise DetectionConfigError(f"{file_path.name}: no hay reglas definidas.")
    return rules


@lru_cache(maxsize=8)
def load_rules_cached(path_str: str | None = None) -> List[RuleConfig]:
    return load_rules(Path(path_str) if path_str else None)


def default_rule_map() -> Dict[str, RuleConfig]:
    return {r.id: r for r in load_rules_cached(None)}


def describe_rules() -> List[Dict[str, Any]]:
    return [
        {
            "id": r.id,
            "name": r.name,
            "category": r.category,
            "base_severity": r.base_severity,
            "enabled": r.enabled,
            "mitre": r.mitre,
            "description": r.description,
            "required_fields": r.required_fields,
            "parameters": r.parameters,
        }
        for r in load_rules_cached(None)
    ]
