# ai/settings.py - Configuracion de IA leida del entorno (.env del backend).
# Sin secretos en el codigo y sin exponer claves: la vista publica solo informa
# si la clave esta configurada (PLAN seccion 10 y 11).
import os
from dataclasses import dataclass

PROVIDERS = ("none", "gemini", "anthropic", "openai_compatible", "ollama")
# Proveedores cloud: el trafico sale de la maquina -> enmascaramiento reversible.
CLOUD_PROVIDERS = ("gemini", "anthropic", "openai_compatible")
# Ollama es local: sin enmascaramiento por defecto (PLAN seccion 10).
LOCAL_PROVIDERS = ("ollama",)

_OLLAMA_DEFAULT_BASE = "http://127.0.0.1:11434"


@dataclass
class AiSettings:
    provider: str
    model: str
    base_url: str
    api_key: str  # solo uso interno; NUNCA se devuelve por la API ni se loguea
    temperature: float
    timeout_seconds: int
    max_output_tokens: int


def load_ai_settings() -> AiSettings:
    provider = (os.getenv("AI_PROVIDER") or "none").strip().casefold()
    if provider not in PROVIDERS:
        provider = "none"
    return AiSettings(
        provider=provider,
        model=(os.getenv("AI_MODEL") or "").strip(),
        base_url=(os.getenv("AI_BASE_URL") or "").strip(),
        api_key=os.getenv("AI_API_KEY") or "",
        temperature=_env_float("AI_TEMPERATURE", 0.1),
        timeout_seconds=_env_int("AI_TIMEOUT_SECONDS", 30),
        max_output_tokens=_env_int("AI_MAX_OUTPUT_TOKENS", 2000),
    )


def effective_provider(settings: AiSettings) -> str:
    """Proveedor realmente usable: sin modelo (o sin clave en los cloud) cae a 'none'."""
    if settings.provider == "none":
        return "none"
    if not settings.model:
        return "none"
    if settings.provider in CLOUD_PROVIDERS and not settings.api_key:
        return "none"
    return settings.provider


def uses_masking(provider: str) -> bool:
    return provider in CLOUD_PROVIDERS


def public_view(settings: AiSettings) -> dict:
    """Vista segura para la UI: nunca incluye la clave ni ningun secreto."""
    eff = effective_provider(settings)
    return {
        "provider": settings.provider,
        "effective_provider": eff,
        "model": settings.model,
        "base_url": settings.base_url if settings.provider in ("openai_compatible", "ollama") else "",
        "key_configured": bool(settings.api_key),
        "temperature": settings.temperature,
        "timeout_seconds": settings.timeout_seconds,
        "mode": "ia" if eff != "none" else "plantillas",
        "providers_available": list(PROVIDERS),
    }


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name) or default)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name) or default)
    except ValueError:
        return default
