# correlation/loader.py - Carga y validacion de la configuracion de correlacion (fase C).
# Mismo enfoque que detection/loader.py: falla rapido ante config invalida, sin valores
# del archivo cargado en el codigo.
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

CONFIG_FILE = Path(__file__).resolve().parent / "config.yaml"
SEVERITIES = ("Bajo", "Medio", "Alto", "Crítico")


class CorrelationConfigError(ValueError):
    """Configuracion de correlacion invalida (clave ausente, tipo incorrecto, etc.)."""


@dataclass
class CorrelationConfig:
    window_minutes: int
    non_linking_user_rules: List[str] = field(default_factory=list)
    base_scores: Dict[str, int] = field(default_factory=dict)
    bands: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    factor_points: Dict[str, int] = field(default_factory=dict)
    factors_cap: int = 30
    multi_host_min: int = 3
    evasion_rules: List[str] = field(default_factory=list)
    repetition_rules: List[str] = field(default_factory=list)
    persistence_categories: List[str] = field(default_factory=list)
    privileged_categories: List[str] = field(default_factory=list)
    privileged_user_patterns: List[str] = field(default_factory=list)
    critical_host_patterns: List[str] = field(default_factory=list)
    incident_phase_bonus: int = 5
    incident_bonus_cap: int = 15
    kill_chain_prefixes: Dict[str, str] = field(default_factory=dict)
    kill_chain_default: str = "Actividad observada"
    kill_chain_phase_order: List[str] = field(default_factory=list)
    override_classifications: List[str] = field(default_factory=list)
    override_max_reason_chars: int = 2000


def _as_int(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CorrelationConfigError(f"{where}: se esperaba un entero.")
    return value


def _as_str_list(value: Any, where: str) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
        raise CorrelationConfigError(f"{where}: se esperaba una lista de textos no vacios.")
    return list(value)


def _validate(data: Any, source: str) -> CorrelationConfig:
    if not isinstance(data, dict):
        raise CorrelationConfigError(f"{source}: estructura esperada {{ window_minutes, scoring, kill_chain, overrides }}.")
    window = _as_int(data.get("window_minutes"), f"{source}: window_minutes")
    if window <= 0:
        raise CorrelationConfigError(f"{source}: window_minutes debe ser positivo.")

    sc = data.get("scoring") or {}
    if not isinstance(sc, dict):
        raise CorrelationConfigError(f"{source}: 'scoring' debe ser un objeto.")

    base = sc.get("base_scores") or {}
    if not isinstance(base, dict):
        raise CorrelationConfigError(f"{source}: scoring.base_scores debe ser un objeto.")
    for sev in SEVERITIES:
        pts = _as_int(base.get(sev), f"{source}: base_scores.{sev}")
        if not 0 <= pts <= 100:
            raise CorrelationConfigError(f"{source}: base_scores.{sev} fuera de rango 0-100.")

    bands_raw = sc.get("bands") or {}
    if not isinstance(bands_raw, dict):
        raise CorrelationConfigError(f"{source}: scoring.bands debe ser un objeto.")
    bands: Dict[str, Tuple[int, int]] = {}
    for sev in SEVERITIES:
        raw = bands_raw.get(sev) or {}
        lo, hi = _as_int(raw.get("min"), f"{source}: bands.{sev}.min"), _as_int(raw.get("max"), f"{source}: bands.{sev}.max")
        if lo > hi:
            raise CorrelationConfigError(f"{source}: bands.{sev} tiene min > max.")
        bands[sev] = (lo, hi)

    points_raw = sc.get("factor_points") or {}
    if not isinstance(points_raw, dict) or not points_raw:
        raise CorrelationConfigError(f"{source}: scoring.factor_points debe ser un objeto con factores.")
    factor_points = {
        str(k): _as_int(v, f"{source}: factor_points.{k}")
        for k, v in points_raw.items()
    }

    factors_cap = _as_int(sc.get("factors_cap", 30), f"{source}: factors_cap")
    if factors_cap < 0:
        raise CorrelationConfigError(f"{source}: factors_cap no puede ser negativo.")

    bonus = _as_int(sc.get("incident_phase_bonus", 5), f"{source}: incident_phase_bonus")
    bonus_cap = _as_int(sc.get("incident_bonus_cap", 15), f"{source}: incident_bonus_cap")
    if bonus < 0 or bonus_cap < 0:
        raise CorrelationConfigError(f"{source}: los bonus de incidente no pueden ser negativos.")

    kc = data.get("kill_chain") or {}
    if not isinstance(kc, dict):
        raise CorrelationConfigError(f"{source}: 'kill_chain' debe ser un objeto.")
    prefixes_raw = kc.get("prefixes") or {}
    if not isinstance(prefixes_raw, dict) or not prefixes_raw:
        raise CorrelationConfigError(f"{source}: kill_chain.prefixes debe ser un objeto prefijo -> fase.")
    prefixes = {str(k): str(v) for k, v in prefixes_raw.items()}
    phase_order = _as_str_list(kc.get("phase_order", []), f"{source}: kill_chain.phase_order")

    ov = data.get("overrides") or {}
    if not isinstance(ov, dict):
        raise CorrelationConfigError(f"{source}: 'overrides' debe ser un objeto.")
    classifications = _as_str_list(ov.get("classifications", []), f"{source}: overrides.classifications")
    if not classifications:
        raise CorrelationConfigError(f"{source}: overrides.classifications no puede estar vacio.")

    return CorrelationConfig(
        window_minutes=window,
        non_linking_user_rules=_as_str_list(data.get("non_linking_user_rules", []), f"{source}: non_linking_user_rules"),
        base_scores={s: int(base[s]) for s in SEVERITIES},
        bands={s: bands[s] for s in SEVERITIES},
        factor_points=factor_points,
        factors_cap=factors_cap,
        multi_host_min=_as_int(sc.get("multi_host_min", 3), f"{source}: multi_host_min"),
        evasion_rules=_as_str_list(sc.get("evasion_rules", []), f"{source}: evasion_rules"),
        repetition_rules=_as_str_list(sc.get("repetition_rules", []), f"{source}: repetition_rules"),
        persistence_categories=_as_str_list(sc.get("persistence_categories", []), f"{source}: persistence_categories"),
        privileged_categories=_as_str_list(sc.get("privileged_categories", []), f"{source}: privileged_categories"),
        privileged_user_patterns=_as_str_list(sc.get("privileged_user_patterns", []), f"{source}: privileged_user_patterns"),
        critical_host_patterns=_as_str_list(sc.get("critical_host_patterns", []), f"{source}: critical_host_patterns"),
        incident_phase_bonus=bonus,
        incident_bonus_cap=bonus_cap,
        kill_chain_prefixes=prefixes,
        kill_chain_default=str(kc.get("default") or "Actividad observada"),
        kill_chain_phase_order=phase_order,
        override_classifications=classifications,
        override_max_reason_chars=_as_int(ov.get("max_reason_chars", 2000), f"{source}: overrides.max_reason_chars"),
    )


def load_config(path: Path | None = None) -> CorrelationConfig:
    file_path = path or CONFIG_FILE
    with open(file_path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return _validate(data, file_path.name)


@lru_cache(maxsize=4)
def load_config_cached(path_str: str | None = None) -> CorrelationConfig:
    return load_config(Path(path_str) if path_str else None)
