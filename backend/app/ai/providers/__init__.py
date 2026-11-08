# ai/providers/ - Adaptadores REST por proveedor (fase E).
# Sin SDKs: peticiones httpx directas. Sin claves en el codigo (vienen de .env o
# de los ajustes en RAM de la UI).
import re

from app.ai.base import AIProviderError, BaseAdapter, require_model
from app.ai.settings import _OLLAMA_DEFAULT_BASE


class OpenAICompatibleAdapter(BaseAdapter):
    """Cualquier API compatible OpenAI (LM Studio, vLLM, Azure-style, etc.)."""

    name: str = "openai_compatible"

    def _base(self) -> str:
        base = (getattr(self.settings, "base_url", "") or "").rstrip("/")
        if not base:
            raise AIProviderError(
                "AI_BASE_URL es obligatorio para openai_compatible (por ejemplo http://127.0.0.1:8000/v1)."
            )
        if not base.endswith("/v1"):
            base += "/v1"
        return base

    def _headers(self) -> dict:
        key = getattr(self.settings, "api_key", "")
        return {"Authorization": f"Bearer {key}"} if key else {}

    def test_connection(self) -> dict:
        self._request("GET", f"{self._base()}/models", headers=self._headers())
        return {"ok": True, "detail": "Conexion correcta con el endpoint compatible OpenAI."}

    def _body(self, model: str, system: str, user: str) -> dict:
        return {
            "model": model,
            "temperature": self.settings.temperature,
            "max_tokens": self.settings.max_output_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }

    def generate(self, system: str, user: str) -> str:
        model = require_model(self.settings)
        resp = self._request(
            "POST",
            f"{self._base()}/chat/completions",
            headers=self._headers(),
            json=self._body(model, system, user),
        )
        data = resp.json()
        try:
            message = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AIProviderError(
                "La respuesta del endpoint compatible OpenAI no tiene el formato esperado."
            ) from exc
        content = str(message.get("content") or "")
        # Algunos modelos (GLM, DeepSeek, Qwen) incrustan el razonamiento en el propio
        # content dentro de bloques <think ...>...</think: se elimina antes de validar.
        content = re.sub(r"<think[^>]*>.*?</think\s*>", "", content, flags=re.DOTALL | re.IGNORECASE)
        # Si el bloque quedo abierto (respuesta truncada a mitad del razonamiento).
        content = re.sub(r"<think[^>]*>.*$", "", content, flags=re.DOTALL | re.IGNORECASE)
        content = content.strip()
        if not content:
            reasoning = message.get("reasoning") or message.get("reasoning_content") or ""
            raise AIProviderError(
                "El modelo no devolvio contenido final: probablemente agoto el presupuesto de "
                "tokens en el modo razonamiento o solo devolvio 'reasoning'. Usa un modelo de "
                "chat sin razonamiento o sube AI_MAX_OUTPUT_TOKENS."
                + (f" (reasoning recibido: {len(str(reasoning))} caracteres)." if reasoning else "")
            )
        return content


class AnthropicAdapter(BaseAdapter):
    name: str = "anthropic"

    BASE = "https://api.anthropic.com"

    def _headers(self) -> dict:
        return {
            "x-api-key": self.settings.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

    def test_connection(self) -> dict:
        model = require_model(self.settings)
        self._request(
            "POST",
            f"{self.BASE}/v1/messages",
            headers=self._headers(),
            json={
                "model": model,
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "ping"}],
            },
        )
        return {"ok": True, "detail": "Conexion correcta con Anthropic."}

    def generate(self, system: str, user: str) -> str:
        model = require_model(self.settings)
        resp = self._request(
            "POST",
            f"{self.BASE}/v1/messages",
            headers=self._headers(),
            json={
                "model": model,
                "max_tokens": self.settings.max_output_tokens,
                "temperature": self.settings.temperature,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        data = resp.json()
        try:
            return "".join(part.get("text", "") for part in data["content"])
        except (KeyError, TypeError) as exc:
            raise AIProviderError(
                "La respuesta de Anthropic no tiene el formato esperado."
            ) from exc


class GeminiAdapter(BaseAdapter):
    name: str = "gemini"

    BASE = "https://generativelanguage.googleapis.com"

    def _headers(self) -> dict:
        # La clave viaja en cabecera, nunca en la URL (no acaba en logs de servidor).
        return {"x-goog-api-key": self.settings.api_key}

    def test_connection(self) -> dict:
        self._request("GET", f"{self.BASE}/v1beta/models", headers=self._headers())
        return {"ok": True, "detail": "Conexion correcta con Gemini."}

    def generate(self, system: str, user: str) -> str:
        model = require_model(self.settings)
        resp = self._request(
            "POST",
            f"{self.BASE}/v1beta/models/{model}:generateContent",
            headers=self._headers(),
            json={
                "system_instruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": {
                    "temperature": self.settings.temperature,
                    "maxOutputTokens": self.settings.max_output_tokens,
                    "responseMimeType": "application/json",
                },
            },
        )
        data = resp.json()
        try:
            parts = data["candidates"][0]["content"]["parts"]
            return "".join(part.get("text", "") for part in parts)
        except (KeyError, IndexError, TypeError) as exc:
            raise AIProviderError(
                "La respuesta de Gemini no tiene el formato esperado."
            ) from exc


class OllamaAdapter(BaseAdapter):
    name: str = "ollama"

    def _base(self) -> str:
        return (getattr(self.settings, "base_url", "") or _OLLAMA_DEFAULT_BASE).rstrip("/")

    def test_connection(self) -> dict:
        model = require_model(self.settings)
        resp = self._request("GET", f"{self._base()}/api/tags")
        models = [m.get("name", "") for m in resp.json().get("models", [])]
        if models and not any(model == m or m.startswith(model + ":") for m in models):
            return {
                "ok": True,
                "detail": (
                    "Ollama responde, pero el modelo configurado no aparece en su lista."
                    " Comprueba AI_MODEL."
                ),
            }
        return {"ok": True, "detail": "Conexion correcta con Ollama."}

    def generate(self, system: str, user: str) -> str:
        model = require_model(self.settings)
        resp = self._request(
            "POST",
            f"{self._base()}/api/chat",
            json={
                "model": model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "options": {"temperature": self.settings.temperature},
            },
        )
        data = resp.json()
        try:
            return str(data["message"]["content"])
        except (KeyError, TypeError) as exc:
            raise AIProviderError("La respuesta de Ollama no tiene el formato esperado.") from exc


_ADAPTERS = {
    OpenAICompatibleAdapter.name: OpenAICompatibleAdapter,
    AnthropicAdapter.name: AnthropicAdapter,
    GeminiAdapter.name: GeminiAdapter,
    OllamaAdapter.name: OllamaAdapter,
}


def get_adapter(provider: str, settings, transport=None) -> BaseAdapter:
    cls = _ADAPTERS.get(provider)
    if cls is None:
        raise AIProviderError(f"Proveedor de IA no soportado: '{provider}'.")
    adapter = cls(settings=settings, _transport=transport)
    # El __init__ de BaseAdapter pone name="" (default del campo de la dataclass);
    # los adaptadores definen su nombre como atributo de clase, no como campo.
    adapter.name = provider
    return adapter
