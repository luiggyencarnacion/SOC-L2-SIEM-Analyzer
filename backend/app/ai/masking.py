# ai/masking.py - Enmascaramiento reversible para proveedores cloud (PLAN seccion 10).
# Los valores reales (IPs, usuarios, hosts, destinos, IoCs) se sustituyen por
# marcadores antes de salir de la maquina y se restauran en la respuesta.
# Ollama (local) no se enmascara por defecto. Los Log_ID y timestamps NO se
# enmascaran: el validador exige citas reales y las horas son parte de la evidencia.
from typing import Any, Dict, Iterable, List

_PREFIX = {
    "user": "USUARIO",
    "host": "HOST",
    "ip": "IP",
    "destination": "DESTINO",
    "value": "VALOR",
}


def build_mask(entity_groups: Dict[str, Iterable[str]]) -> Dict[str, str]:
    """Construye el mapa valor->marcador de forma determinista.

    entity_groups: {"user": [...], "host": [...], "ip": [...], "destination": [...], "value": [...]}
    """
    mapping: Dict[str, str] = {}
    counters = {k: 0 for k in _PREFIX}
    # Longitud descendente primero: evita que un valor substring de otro
    # se reemplace dos veces; empates por valor para determinismo.
    items: List[tuple] = []
    for kind, values in entity_groups.items():
        prefix = _PREFIX.get(kind, "VALOR")
        for v in values:
            if v and len(str(v)) >= 3:
                items.append((str(v), prefix))
    items.sort(key=lambda t: (-len(t[0]), t[0], t[1]))
    for value, prefix in items:
        if value in mapping:
            continue
        counters[prefix] = counters.get(prefix, 0) + 1
        mapping[value] = f"[{prefix}_{counters[prefix]}]"
    return mapping


def mask_text(text: str, mapping: Dict[str, str]) -> str:
    for value, placeholder in mapping.items():
        if value in text:
            text = text.replace(value, placeholder)
    return text


def unmask_text(text: str, mapping: Dict[str, str]) -> str:
    reverse = {placeholder: value for value, placeholder in mapping.items()}
    for placeholder, value in reverse.items():
        if placeholder in text:
            text = text.replace(placeholder, value)
    return text


def mask_payload(obj: Any, mapping: Dict[str, str]) -> Any:
    """Aplica el enmascaramiento recursivamente a strings del payload."""
    if isinstance(obj, str):
        return mask_text(obj, mapping)
    if isinstance(obj, dict):
        return {k: mask_payload(v, mapping) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_payload(v, mapping) for v in obj]
    return obj
