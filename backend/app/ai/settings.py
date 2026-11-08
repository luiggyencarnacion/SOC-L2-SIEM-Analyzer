# ai/settings.py - Configuracion de IA: .env del backend + ajustes en caliente desde la UI.
# Decision aprobada por el desarrollador (post-F, desviacion puntual del PLAN 10):
#   - La clave PUEDE introducirse desde la UI, pero se guarda SOLO en memoria del
#     proceso: nunca se persiste en disco, nunca se devuelve por la API y desaparece
#     al reiniciar el backend.
#   - El .env sigue admitido como alternativa; el override de la UI tiene prioridad.
#   - La vista publica solo informa de si la clave esta configurada (PLAN 10 y 11).
import os
import threading
from dataclasses import dataclass
from typing import Any, Dict

PROVIDERS = ("none", "gemini", "anthropic", "openai_compatible", "ollama")
# Proveedores cloud: el trafico sale de la maquina -> enmascaramiento reversible.
CLOUD_PROVIDERS = ("gemini", "anthropic", "openai_compatible")
# Ollama es local: sin enmascaramiento por defecto (PLAN seccion 10).
LOCAL_PROVIDERS = ("ollama",)

_OLLAMA_DEFAULT_BASE = "http://127.0.0.1:11434"

# Override en RAM (ajustes desde la UI). Nunca se escribe a disco.
_rt_lock = threading.Lock()
_runtime: Dict[str, Any] = {}

_MAX_MODEL_CHARS = 200
_MAX_BASE_URL_CHARS = 500
_MAX_API_KEY_CHARS = 500


class SettingsError(ValueError):
    """Valor invalido en los ajustes de IA (se traduce en HTTP 400)."""


@dataclass
class AiSettings:
    provider: str
    model: str
    base_url: str
    api_key: str  # solo uso interno; NUNCA se devuelve por la API ni se loguea
    temperature: float
    timeout_seconds: int
    max_output_tokens: int


def _validate(provider: Any, model: Any, base_url: Any, temperature: Any, api_key: Any) -> Dict[str, Any]:
    """Valida los valores del formulario de la UI y devuelve el override limpio."""
    out: Dict[str, Any] = {}
    if provider is not None:
        p = str(provider).strip().casefold()
        if p not in PROVIDERS:
            raise SettingsError(
                f"Proveedor no valido: '{provider}'. Valores admitidos: {', '.join(PROVIDERS)}."
            )
        out["provider"] = p
    if model is not None:
        m = str(model).strip()
        if len(m) > _MAX_MODEL_CHARS:
            raise SettingsError(f"El modelo no puede superar {_MAX_MODEL_CHARS} caracteres.")
        out["model"] = m
    if base_url is not None:
        b = str(base_url).strip()
        if len(b) > _MAX_BASE_URL_CHARS:
            raise SettingsError(f"La base URL no puede superar {_MAX_BASE_URL_CHARS} caracteres.")
        out["base_url"] = b
    if temperature is not None:
        try:
            t = float(temperature)
        except (TypeError, ValueError):
            raise SettingsError("La temperatura debe ser un numero.")
        if not (0.0 <= t <= 2.0):
            raise SettingsError("La temperatura debe estar entre 0 y 2.")
        out["temperature"] = t
    if api_key is not None:
        k = str(api_key).strip()
        if len(k) > _MAX_API_KEY_CHARS:
            raise SettingsError(f"La clave no puede superar {_MAX_API_KEY_CHARS} caracteres.")
        out["api_key"] = k
    return out


def set_runtime_settings(
    provider: Any = None,
    model: Any = None,
    base_url: Any = None,
    temperature: Any = None,
    api_key: Any = None,
) -> None:
    """Guarda ajustes en RAM (viven hasta reiniciar el backend). api_key=None no la toca."""
    clean = _validate(provider, model, base_url, temperature, api_key)
    with _rt_lock:
        _runtime.update(clean)


def clear_runtime_key() -> None:
    """Borra SOLO la clave de RAM (vuelve a la del .env, si la hubiera)."""
    with _rt_lock:
        _runtime.pop("api_key", None)


def clear_runtime_settings() -> None:
    """Restablece todos los ajustes de RAM; la configuracion vuelve a salir del .env."""
    with _rt_lock:
        _runtime.clear()


def runtime_is_active() -> bool:
    with _rt_lock:
        return bool(_runtime)


def load_ai_settings() -> AiSettings:
    with _rt_lock:
        rt = dict(_runtime)
    provider = str(rt.get("provider") or (os.getenv("AI_PROVIDER") or "none")).strip().casefold()
    if provider not in PROVIDERS:
        provider = "none"
    return AiSettings(
        provider=provider,
        model=str(rt.get("model") or os.getenv("AI_MODEL") or "").strip(),
        base_url=str(rt.get("base_url") or os.getenv("AI_BASE_URL") or "").strip(),
        api_key=str(rt.get("api_key") if rt.get("api_key") is not None else (os.getenv("AI_API_KEY") or "")),
        temperature=(
            rt["temperature"] if "temperature" in rt else _env_float("AI_TEMPERATURE", 0.1)
        ),
        timeout_seconds=_env_int("AI_TIMEOUT_SECONDS", 180),
        max_output_tokens=_env_int("AI_MAX_OUTPUT_TOKENS", 6000),
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
