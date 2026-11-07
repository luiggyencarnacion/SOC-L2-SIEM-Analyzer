# detection/impl/__init__.py - Registro de implementaciones por categoria.
# Cada modulo declara RULES: {id de regla -> handler(ctx, rule, state) -> (findings, status, reason)}
from app.detection.impl import auth, execution, exfil, lateral, persistence, privilege, web

REGISTRY = {}


def _merge(module) -> None:
    for rid, handler in getattr(module, "RULES", {}).items():
        if rid in REGISTRY:
            raise ValueError(f"Regla '{rid}' implementada en mas de un modulo.")
        REGISTRY[rid] = handler


for _m in (auth, privilege, execution, persistence, lateral, exfil, web):
    _merge(_m)


def handler_for(rule_id: str):
    return REGISTRY.get(rule_id)
