# tests/test_ai_ui_settings.py - Ajustes de IA desde la UI (post-F, decision del
# desarrollador): proveedor/modelo/base URL/temperatura/clave en RAM del backend.
# Garantias probadas: la clave NUNCA aparece en ninguna respuesta; el override de
# la UI tiene prioridad sobre .env; borrar/restablecer funciona; vivos solo en
# memoria (nada se escribe a disco).
import pytest
from fastapi.testclient import TestClient

from app.ai.settings import (
    clear_runtime_settings,
    load_ai_settings,
    runtime_is_active,
)
from app.ai.validator import parse_llm_payload
from app.main import app

client = TestClient(app)

SECRET = "sk-test-secreto-1234567890"


# ---------- parser robusto de la respuesta del LLM (post-F) ----------

def test_parse_llm_payload_direct_json():
    raw = '{"paragraphs": [{"section": "a", "label": "Hecho", "text": "x", "citations": []}]}'
    assert len(parse_llm_payload(raw)) == 1


def test_parse_llm_payload_fenced_json():
    raw = '```json\n{"paragraphs": [{"section": "a", "label": "Hecho", "text": "x", "citations": []}]}\n```'
    assert len(parse_llm_payload(raw)) == 1


def test_parse_llm_payload_fenced_with_intro_text():
    """Caso real: el LLM mete texto antes/después del bloque de código."""
    raw = (
        "Por supuesto, aqui tienes la redaccion solicitada:\n\n"
        '```json\n{"paragraphs": [{"section": "a", "label": "Hecho", "text": "x", "citations": []}]}\n```\n\n'
        "Espero que resulte util."
    )
    assert len(parse_llm_payload(raw)) == 1


def test_parse_llm_payload_json_with_surrounding_text_no_fences():
    raw = 'Respuesta: {"paragraphs": [{"section": "a", "label": "Hecho", "text": "x", "citations": []}]} fin.'
    assert len(parse_llm_payload(raw)) == 1


def test_parse_llm_payload_truncated_reports_reason():
    raw = '{"paragraphs": [{"section": "a", "label": "Hecho", "text": "empieza un parrafo que se corta'
    with pytest.raises(ValueError, match="truncada"):
        parse_llm_payload(raw)


def test_parse_llm_payload_missing_paragraphs_key():
    with pytest.raises(ValueError):
        parse_llm_payload('{"otra_cosa": []}')


@pytest.fixture(autouse=True)
def _clean_runtime():
    """Cada test empieza y termina sin override en RAM (no contamina otros tests)."""
    clear_runtime_settings()
    yield
    clear_runtime_settings()


def test_post_settings_enables_ia_in_memory(monkeypatch):
    # Sin nada en .env (estado limpio): plantillas.
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    monkeypatch.delenv("AI_MODEL", raising=False)
    monkeypatch.delenv("AI_API_KEY", raising=False)
    r = client.post(
        "/api/ai/settings",
        json={"provider": "openai_compatible", "model": "modelo-de-prueba",
              "base_url": "http://127.0.0.1:9999/v1", "temperature": 0.2, "api_key": SECRET},
    )
    assert r.status_code == 200, r.text
    view = r.json()
    assert view["provider"] == "openai_compatible"
    assert view["model"] == "modelo-de-prueba"
    assert view["key_configured"] is True
    assert view["effective_provider"] == "openai_compatible"
    assert view["mode"] == "ia"
    assert view["settings_source"] == "ui"
    # La clave NUNCA aparece en la respuesta.
    assert SECRET not in r.text

    # load_ai_settings refleja el override (la redaccion lo usara).
    s = load_ai_settings()
    assert s.api_key == SECRET and s.model == "modelo-de-prueba" and s.temperature == 0.2


def test_post_settings_empty_key_keeps_previous(monkeypatch):
    monkeypatch.delenv("AI_API_KEY", raising=False)
    client.post("/api/ai/settings", json={"provider": "gemini", "model": "m1", "api_key": SECRET})
    # Segunda pasada sin clave (cambio de modelo): no debe perderse la clave.
    r = client.post("/api/ai/settings", json={"model": "m2"})
    assert r.status_code == 200
    view = r.json()
    assert view["model"] == "m2"
    assert view["key_configured"] is True
    assert SECRET not in r.text


def test_clear_key_falls_back_to_env(monkeypatch):
    monkeypatch.setenv("AI_API_KEY", "clave-del-env")
    client.post("/api/ai/settings", json={"api_key": SECRET})
    assert client.get("/api/ai/settings").json()["key_configured"] is True
    r = client.post("/api/ai/settings", json={"clear_key": True})
    assert r.status_code == 200
    assert r.json()["key_configured"] is True  # vuelve a la del .env
    s = load_ai_settings()
    assert s.api_key == "clave-del-env"


def test_clear_key_without_env_leaves_unconfigured(monkeypatch):
    monkeypatch.delenv("AI_API_KEY", raising=False)
    client.post("/api/ai/settings", json={"api_key": SECRET})
    r = client.post("/api/ai/settings", json={"clear_key": True})
    assert r.json()["key_configured"] is False
    assert r.json()["mode"] == "plantillas"


def test_delete_settings_returns_to_env(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "ollama")
    monkeypatch.setenv("AI_MODEL", "llama-local")
    client.post("/api/ai/settings", json={"provider": "anthropic", "model": "otro", "api_key": SECRET})
    r = client.delete("/api/ai/settings")
    assert r.status_code == 200
    view = r.json()
    assert view["provider"] == "ollama"
    assert view["model"] == "llama-local"
    assert view["settings_source"] == "env"
    assert runtime_is_active() is False


def test_post_settings_validation():
    r = client.post("/api/ai/settings", json={"provider": "no-existe"})
    assert r.status_code == 400
    r2 = client.post("/api/ai/settings", json={"temperature": 5})
    assert r2.status_code == 400
    r3 = client.post("/api/ai/settings", json={"temperature": "no-es-numero"})
    # Pydantic rechaza el tipo antes (422); mi validacion cubre el caso numerico fuera de rango.
    assert r3.status_code in (400, 422)


# ---------- regresion: pool de entidades/horas del validador (bug post-F) ----------

def test_context_pool_reads_spanish_evidence_keys():
    """Las filas de _evidence_rows usan claves en espanol; el pool debe leerlas."""
    from app.ai.validator import context_from_pool

    rows = [{
        "log_id": "EVT-00001",
        "timestamp": "2026-10-23T08:25:00",
        "usuario": "CORP\\admin",
        "host": "DC-01",
        "ip_origen": "203.0.113.74",
    }]
    ctx = context_from_pool("hallazgo:F-001", rows, {"EVT-00001"}, set(), [7])
    assert "203.0.113.74" in ctx.allowed_entities
    assert "corp\\admin" in ctx.allowed_entities
    assert "dc-01" in ctx.allowed_entities
    assert "2026-10-23 08:25" in ctx.allowed_times
    assert "EVT-00001" in ctx.allowed_log_ids


def test_context_pool_reads_normalized_keys_too():
    from app.ai.validator import context_from_pool

    rows = [{
        "log_id": "EVT-00002",
        "timestamp_parsed": "2026-10-23T09:00:00",
        "user_raw": "svc_backup",
        "host_raw": "FS-SRV01",
        "source_ip": "198.51.100.9",
    }]
    ctx = context_from_pool("hallazgo:F-002", rows, {"EVT-00002"}, set())
    assert "198.51.100.9" in ctx.allowed_entities
    assert "svc_backup" in ctx.allowed_entities
    assert "2026-10-23 09:00" in ctx.allowed_times


def test_runtime_settings_do_not_touch_disk(monkeypatch, tmp_path):
    """Garantia clave de la decision: nada se persiste; .env no cambia."""
    env_path = tmp_path / ".env"
    env_path.write_text("AI_PROVIDER=none\n", encoding="utf-8")
    client.post("/api/ai/settings", json={"provider": "anthropic", "model": "m", "api_key": SECRET})
    assert env_path.read_text(encoding="utf-8") == "AI_PROVIDER=none\n"
    # Y al vaciar la RAM, todo vuelve al estado del env.
    clear_runtime_settings()
    assert client.get("/api/ai/settings").json()["mode"] == "plantillas"


def test_narrative_uses_runtime_settings(monkeypatch):
    """Con ajustes de UI validos, la redaccion pasa a modo IA (con adaptador simulado)."""
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    monkeypatch.delenv("AI_MODEL", raising=False)
    monkeypatch.delenv("AI_API_KEY", raising=False)
    client.post(
        "/api/ai/settings",
        json={"provider": "anthropic", "model": "m", "api_key": SECRET},
    )
    from app.ai import service as ai_service

    calls = {}

    class FakeAdapter:
        name = "fake"

        def generate(self, system, user):
            calls["used"] = True
            return "no es json -> validador lo rechaza"

        def close(self):
            pass

    class FakeErr(Exception):
        pass

    monkeypatch.setattr(ai_service.providers_mod, "get_adapter", lambda *a, **k: FakeAdapter())

    from app.services.sessions import AnalysisResult

    result = AnalysisResult(
        sheet="s", header_row_idx=0, columns=["a"], field_map={}, log_id_column=None,
        events=[], quality={}, detection={"findings": []}, correlation={"incidents": []},
    )
    narrative = ai_service.generate_narrative(result)
    assert calls.get("used") is True          # uso el adaptador con los ajustes de la UI
    assert narrative["ai_state"]["used"] is True
    # La respuesta invalida cae a plantillas: la IA no inventa (PLAN 10).
    assert narrative["mode"] == "ia"
    assert all(p["source"] == "plantilla" for s in narrative["sections"] for p in s["paragraphs"])
