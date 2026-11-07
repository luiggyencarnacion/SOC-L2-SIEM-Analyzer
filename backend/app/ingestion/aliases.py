# ingestion/aliases.py - Relaciones de identidades host/usuario (fase A).
# Politica (PLAN seccion 4.2):
# - exact: mis claves canonicas... misma clave y mismos valores crudos (tras limpiar espacios/mayusculas).
# - probable: misma clave normalizada, valores crudos distintos -> inferencia etiquetada.
# - candidate: valores parecidos pero claves distintas -> NO se fusionan.
# - El analista podra confirmar/rechazar en fases posteriores; aqui solo deteccion de base.
from collections import defaultdict
from typing import Any, Dict, Iterable, List

from app.ingestion.normalize import normalize_key

MAX_CANDIDATE_PAIRS = 200  # Tope de memoria/performance


def _longest_common_substring(a: str, b: str) -> int:
    """Longitud del mayor substring comun (sin considerar orden)."""
    if not a or not b:
        return 0
    prev = [0] * (len(b) + 1)
    best = 0
    for i in range(1, len(a) + 1):
        cur = [0] * (len(b) + 1)
        for j in range(1, len(b) + 1):
            if a[i - 1] == b[j - 1]:
                cur[j] = prev[j - 1] + 1
                if cur[j] > best:
                    best = cur[j]
        prev = cur
    return best


def _unique_raw(values: Iterable[Any]) -> List[str]:
    seen: Dict[str, None] = {}
    for v in values:
        if v is None:
            continue
        s = str(v).strip()
        if s and s not in seen:
            seen[s] = None
    return list(seen)


def _strip_context(raw_value: str) -> str:
    """Quita dominio tipo 'DOMINIO\\usuario' para comparar forma, sin tocar el crudo."""
    if "\\" in raw_value:
        return raw_value.split("\\")[-1]
    return raw_value


def build_alias_report(
    host_values: Iterable[Any], user_values: Iterable[Any]
) -> Dict[str, List[Dict[str, Any]]]:
    report: Dict[str, List[Dict[str, Any]]] = {"hosts": [], "users": []}
    for kind, values, out_list in (
        ("host", host_values, report["hosts"]),
        ("user", user_values, report["users"]),
    ):
        raws = _unique_raw(values)
        by_key: Dict[str, List[str]] = defaultdict(list)
        for r in raws:
            by_key[normalize_key(r)].append(r)

        # exact / probable
        for key, members in by_key.items():
            lowers = {m.lower() for m in members}
            if len(members) == 1:
                status, rationale, merged = "exact", "identidad unica", True
            elif len(lowers) == 1:
                status, rationale, merged = "exact", "solo difieren espacios/mayusculas", True
            else:
                status = "probable"
                rationale = "misma clave normalizada, valores crudos distintos (inferencia)"
                merged = False  # fusion suave: la correlacion la reconfirma el analista
            out_list.append(
                {
                    "kind": kind,
                    "status": status,
                    "key": key,
                    "members": members,
                    "merged": merged,
                    "rationale": rationale,
                }
            )

        # candidate: claves distintas pero con solapamiento fuerte (no se fusionan)
        keys = sorted(k for k in by_key if k)
        pairs = 0
        for i in range(len(keys)):
            if pairs >= MAX_CANDIDATE_PAIRS:
                break
            for j in range(i + 1, len(keys)):
                a, b = keys[i], keys[j]
                if not a or not b:
                    continue
                # Longest common substring: solapamiento >= 6 sobre claves que NO son iguales.
                if _longest_common_substring(a, b) >= 6:
                    out_list.append(
                        {
                            "kind": kind,
                            "status": "candidate",
                            "key": a,
                            "members": by_key[a] + by_key[b],
                            "merged": False,
                            "rationale": "valores parecidos con claves distintas; no se fusionan",
                        }
                    )
                    pairs += 1
                    if pairs >= MAX_CANDIDATE_PAIRS:
                        break
    return report
