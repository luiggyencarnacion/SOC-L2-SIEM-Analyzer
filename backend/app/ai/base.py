# ai/base.py - Contrato comun de los adaptadores IA (fase E).
# Adaptadores REST con httpx, sin SDKs (PLAN seccion 2 y 10). Los tests usan
# httpx.MockTransport; nunca se hacen llamadas reales en la suite.
from dataclasses import dataclass, field

import httpx


class AIProviderError(Exception):
    """Error de proveedor con mensaje claro en espanol (sin trazas internas)."""


@dataclass
class AdapterRequestLog:
    status_code: int = 0
    url_host: str = ""
    error: str = ""


@dataclass
class BaseAdapter:
    name: str = ""
    settings: object = None
    _transport: object = None
    last_status: int = 0
    calls: list = field(default_factory=list)

    def __post_init__(self) -> None:
        timeout = getattr(self.settings, "timeout_seconds", 30)
        self._client = httpx.Client(timeout=timeout, transport=self._transport)

    # --- interfaz ---
    def test_connection(self) -> dict:
        raise NotImplementedError

    def generate(self, system: str, user: str) -> str:
        raise NotImplementedError

    # --- utilidades ---
    def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        self.calls.append({"method": method, "url": url})
        try:
            resp = self._client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise AIProviderError(
                f"No se pudo contactar con el proveedor '{self.name}': {exc.__class__.__name__}."
            ) from exc
        self.last_status = resp.status_code
        if resp.status_code >= 400:
            raise AIProviderError(
                f"El proveedor '{self.name}' respondio HTTP {resp.status_code}."
                " Revisa el proveedor, el modelo, la clave y la URL base."
            )
        return resp

    def close(self) -> None:
        self._client.close()


def require_model(settings) -> str:
    model = getattr(settings, "model", "")
    if not model:
        raise AIProviderError("AI_MODEL no esta configurado; la IA no puede activarse sin modelo.")
    return model
