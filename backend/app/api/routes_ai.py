# api/routes_ai.py - Endpoints de la fase E: ajustes IA, prueba de conexion y redaccion.
# PLAN seccion 10: las claves viven solo en .env; la UI nunca las recibe ni las muestra.
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query

from app.ai.base import AIProviderError
from app.ai.settings import effective_provider, load_ai_settings, public_view
from app.services import sessions as store

router = APIRouter(prefix="/api", tags=["ia"])


@router.get("/ai/settings")
def ai_settings() -> Any:
    """Estado de la IA para la pantalla de ajustes (sin exponer la clave)."""
    settings = load_ai_settings()
    return public_view(settings)


@router.post("/ai/test")
def ai_test() -> Any:
    """Prueba de conexion con el proveedor configurado (nunca devuelve la clave)."""
    settings = load_ai_settings()
    provider = effective_provider(settings)
    if provider == "none":
        if settings.provider != "none" and not settings.model:
            detail = (
                f"Proveedor configurado: {settings.provider}, pero AI_MODEL esta vacio; "
                "la redaccion funciona por plantillas deterministas."
            )
        elif settings.provider in ("gemini", "anthropic", "openai_compatible") and not settings.api_key:
            detail = (
                f"Proveedor configurado: {settings.provider}, pero AI_API_KEY no esta configurada; "
                "la redaccion funciona por plantillas deterministas."
            )
        else:
            detail = (
                "Proveedor 'none': la redaccion se genera por plantillas deterministas "
                "sin llamadas externas."
            )
        return {
            "ok": True,
            "provider": settings.provider,
            "effective_provider": "none",
            "mode": "plantillas",
            "detail": detail,
        }
    try:
        from app.ai.providers import get_adapter

        adapter = get_adapter(provider, settings)
        try:
            result = adapter.test_connection()
        finally:
            adapter.close()
        return {
            "ok": True,
            "provider": provider,
            "effective_provider": provider,
            "mode": "ia",
            "detail": result.get("detail", "Conexion correcta."),
        }
    except AIProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@router.post("/sessions/{session_id}/narrative")
def generate_narrative_endpoint(
    session_id: str,
    sheet: Optional[str] = Query(None),
) -> Any:
    """Redacta secciones del informe desde los hallazgos deterministas.

    Con AI_PROVIDER=none todo sale de plantillas; con IA, cada parrafo del LLM
    pasa por el validador anti-alucinacion y los rechazados caen a plantilla.
    """
    s = store.get_session(session_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Sesion no encontrada o expirada.")
    target = sheet or next(iter(s.analyses), None)
    if target is None or target not in s.analyses:
        raise HTTPException(
            status_code=404,
            detail="Esta sesion aun no tiene analisis. Ejecuta /analyze primero.",
        )
    result = s.analyses[target]
    from app.ai.service import generate_narrative

    narrative = generate_narrative(result)
    narrative["session_id"] = session_id
    result.narrative = narrative
    return narrative


@router.get("/sessions/{session_id}/narrative")
def get_narrative(session_id: str, sheet: Optional[str] = Query(None)) -> Any:
    """Devuelve la ultima redaccion generada para la sesion (si existe)."""
    s = store.get_session(session_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Sesion no encontrada o expirada.")
    target = sheet or next(iter(s.analyses), None)
    if target is None or target not in s.analyses:
        raise HTTPException(
            status_code=404,
            detail="Esta sesion aun no tiene analisis. Ejecuta /analyze primero.",
        )
    result = s.analyses[target]
    if not result.narrative:
        raise HTTPException(
            status_code=404,
            detail="Todavia no se ha generado la redaccion para este analisis.",
        )
    return result.narrative
