# tests/test_ai.py - Fase E: ajustes IA, adaptadores (httpx.MockTransport), masking,
# validador anti-alucinacion y redaccion por plantillas con AI_PROVIDER=none.
# Sin llamadas reales a proveedores; sin claves en el codigo.
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.ai.base import AIProviderError
from app.ai.masking import build_mask, mask_payload, mask_text, unmask_text
from app.ai.providers import (
    AnthropicAdapter,
    GeminiAdapter,
    OllamaAdapter,
    OpenAICompatibleAdapter,
    get_adapter,
)
from app.ai.settings import AiSettings, effective_provider, load_ai_settings, public_view
from app.ai.service import generate_narrative
from app.ai.validator import context_from_pool, validate_paragraphs
from app.main import app
from app.reporting.templates import NO_EVIDENCE_PHRASE, finding_paragraphs

client = TestClient(app)

SAMPLE = Path(__file__).resolve().parents[2] / "data" / "sample" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"


# ------------------------------- helpers -------------------------------

def _settings(**overrides) -> AiSettings:
    base = dict(
        provider="none", model="", base_url="", api_key="",
        temperature=0.1, timeout_seconds=5, max_output_tokens=2000,
    )
    base.update(overrides)
    return AiSettings(**base)


def _analyze_sample():
    """Sube y analiza el Excel de ejemplo; devuelve (session_id, sheet)."""
    r = client.post("/api/upload", files={"file": ("logs.xlsx", SAMPLE.read_bytes(), "application/octet-stream")})
    assert r.status_code == 200, r.text
    body = r.json()
    sid = body["session_id"]
    sheet = body["sheets"][0]["name"]
    mapping = [{"column": s["column"], "field": s["field"]} for s in body["mappings"][0]["suggestions"]]
    r2 = client.post(
        f"/api/sessions/{sid}/analyze",
        json={"sheet": sheet, "header_row": body["sheets"][0]["header_row"], "mapping": mapping},
    )
    assert r2.status_code == 200, r2.text
    return sid, sheet


def _fake_adapter(response_text: str):
    class FakeAdapter:
        name = "fake"

        def __init__(self, *a, **k):
            pass

        def close(self):
            pass

        def test_connection(self):
            return {"ok": True, "detail": "ok"}

        def generate(self, system: str, user: str) -> str:
            return response_text

    return FakeAdapter


# ------------------------- ajustes y prueba de conexion -------------------------

def test_settings_por_defecto_plantillas():
    r = client.get("/api/ai/settings")
    assert r.status_code == 200
    body = r.json()
    assert body["provider"] == "none"
    assert body["mode"] == "plantillas"
    assert body["key_configured"] is False
    assert "api_key" not in body and "AI_API_KEY" not in body  # nunca se expone la clave


def test_settings_con_clave_no_expone_el_valor(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    monkeypatch.setenv("AI_MODEL", "claude-test")
    monkeypatch.setenv("AI_API_KEY", "sk-secreto-de-prueba")
    settings = load_ai_settings()
    view = public_view(settings)
    assert view["key_configured"] is True
    assert view["mode"] == "ia"
    assert "sk-secreto-de-prueba" not in json.dumps(view)
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    monkeypatch.delenv("AI_MODEL", raising=False)
    monkeypatch.delenv("AI_API_KEY", raising=False)


def test_cloud_sin_clave_cae_a_plantillas():
    assert effective_provider(_settings(provider="gemini", model="m")) == "none"
    assert effective_provider(_settings(provider="anthropic", model="m", api_key="k")) == "anthropic"
    assert effective_provider(_settings(provider="ollama", model="m")) == "ollama"
    assert effective_provider(_settings(provider="openai_compatible")) == "none"  # sin modelo


def test_test_connection_none():
    r = client.post("/api/ai/test")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert "plantillas" in body["detail"]


def test_test_connection_cloud_sin_clave_informa_plantillas(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "gemini")
    monkeypatch.setenv("AI_MODEL", "gemini-test")
    monkeypatch.delenv("AI_API_KEY", raising=False)
    r = client.post("/api/ai/test")
    assert r.status_code == 200
    assert r.json()["mode"] == "plantillas"
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    monkeypatch.delenv("AI_MODEL", raising=False)


# ------------------------- adaptadores con MockTransport -------------------------

def _mock(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def test_adapter_openai_compatible_generate():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/chat/completions")
        assert request.headers.get("Authorization") == "Bearer clave-test"
        return httpx.Response(200, json={"choices": [{"message": {"content": "parrafo de prueba"}}]})

    ad = OpenAICompatibleAdapter(
        settings=_settings(provider="openai_compatible", model="m", base_url="http://fake.local", api_key="clave-test"),
        _transport=_mock(handler),
    )
    assert ad.generate("sys", "user") == "parrafo de prueba"
    ad.close()


def test_adapter_anthropic_generate():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("x-api-key") == "clave-test"
        return httpx.Response(200, json={"content": [{"type": "text", "text": "parrafo"}]})

    ad = AnthropicAdapter(settings=_settings(provider="anthropic", model="m", api_key="clave-test"), _transport=_mock(handler))
    assert ad.generate("sys", "user") == "parrafo"
    ad.close()


def test_adapter_gemini_generate():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("x-goog-api-key") == "clave-test"
        assert "generateContent" in request.url.path
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "salida"}]}}]})

    ad = GeminiAdapter(settings=_settings(provider="gemini", model="m", api_key="clave-test"), _transport=_mock(handler))
    assert ad.generate("sys", "user") == "salida"
    ad.close()


def test_adapter_ollama_generate():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/api/chat")
        return httpx.Response(200, json={"message": {"content": "local"}})

    ad = OllamaAdapter(settings=_settings(provider="ollama", model="m", base_url="http://127.0.0.1:11434"), _transport=_mock(handler))
    assert ad.generate("sys", "user") == "local"
    ad.close()


def test_adapter_error_http_mensaje_claro():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "bad key"})

    ad = AnthropicAdapter(settings=_settings(provider="anthropic", model="m", api_key="clave-test"), _transport=_mock(handler))
    with pytest.raises(AIProviderError):
        ad.generate("sys", "user")
    ad.close()


def test_get_adapter_desconocido():
    with pytest.raises(AIProviderError):
        get_adapter("no_existe", _settings())


# ------------------------------- masking -------------------------------

def test_masking_reversible():
    mapping = build_mask({"user": ["CORP\\mgarcia"], "ip": ["203.0.113.74"], "host": ["DC-01"]})
    text = "El usuario CORP\\mgarcia desde 203.0.113.74 ataco DC-01 (EVT-00123)."
    masked = mask_text(text, mapping)
    assert "CORP\\mgarcia" not in masked and "203.0.113.74" not in masked and "DC-01" not in masked
    assert "EVT-00123" in masked  # los Log_ID no se enmascaran: deben poder citarse
    assert unmask_text(masked, mapping) == text


def test_masking_payload_recursivo():
    mapping = build_mask({"ip": ["10.0.0.5"]})
    payload = {"a": ["10.0.0.5", "x"], "b": {"c": "10.0.0.5 y mas"}}
    out = mask_payload(payload, mapping)
    assert "10.0.0.5" not in json.dumps(out)
    assert out["a"][1] == "x"


# ---------------------- validador anti-alucinacion ----------------------

def _ctx(section="hallazgo:F-001"):
    events = [
        {
            "log_id": "EVT-0001", "timestamp_parsed": "2026-01-01T10:00:00",
            "user_raw": "CORP\\admin", "host_raw": "DC-01", "source_ip": "203.0.113.9",
            "event_code": "4624", "result_norm": "success", "destination_raw": None,
            "destination_host": None, "destination_ip": None, "url_path": None,
            "share": None, "file_path": None,
        },
        {
            "log_id": "EVT-0002", "timestamp_parsed": "2026-01-01T10:05:00",
            "user_raw": "CORP\\admin", "host_raw": "DC-01", "source_ip": "203.0.113.9",
            "event_code": "4625", "result_norm": "failure", "destination_raw": None,
            "destination_host": None, "destination_ip": None, "url_path": None,
            "share": None, "file_path": None,
        },
    ]
    ctx = context_from_pool(section, events, session_log_ids={"EVT-0001", "EVT-0002", "EVT-9999"}, case_entities={"corp\\admin", "dc-01", "203.0.113.9", "otro-host", "corp\\rrojas"})
    ctx.allowed_entities.update({"auth-002", "f-001"})
    return ctx


def test_validador_acepta_parrafo_valido():
    ctx = _ctx()
    raw = json.dumps({"paragraphs": [{
        "section": "hallazgo:F-001", "label": "Hecho",
        "text": "Se registran 2 eventos 4624/4625 desde 203.0.113.9 contra DC-01 a las 2026-01-01 10:00.",
        "citations": ["EVT-0001"],
    }]}, ensure_ascii=False)
    accepted, rejected = validate_paragraphs(raw, {"hallazgo:F-001": ctx})
    assert len(accepted) == 1 and not rejected
    assert accepted[0]["source"] == "ia_validada"


def test_validador_rechaza_cita_inexistente():
    ctx = _ctx()
    raw = json.dumps({"paragraphs": [{
        "section": "hallazgo:F-001", "label": "Hecho", "text": "x", "citations": ["NOPE-1"],
    }]})
    accepted, rejected = validate_paragraphs(raw, {"hallazgo:F-001": ctx})
    assert not accepted
    assert "no existe" in rejected[0]["reason"]


def test_validador_rechaza_cita_fuera_de_la_evidencia():
    ctx = _ctx()
    raw = json.dumps({"paragraphs": [{
        "section": "hallazgo:F-001", "label": "Hecho", "text": "x", "citations": ["EVT-9999"],
    }]})
    accepted, rejected = validate_paragraphs(raw, {"hallazgo:F-001": ctx})
    assert not accepted
    assert "fuera de la evidencia" in rejected[0]["reason"]


def test_validador_rechaza_ip_inventada():
    ctx = _ctx()
    raw = json.dumps({"paragraphs": [{
        "section": "hallazgo:F-001", "label": "Hecho", "text": "Ataque desde 198.51.100.99.",
        "citations": ["EVT-0001"],
    }]})
    accepted, rejected = validate_paragraphs(raw, {"hallazgo:F-001": ctx})
    assert not accepted
    assert "198.51.100.99" in rejected[0]["reason"]


def test_validador_rechaza_entidad_de_otra_seccion():
    ctx = _ctx()
    raw = json.dumps({"paragraphs": [{
        "section": "hallazgo:F-001", "label": "Hecho", "text": "El usuario corp\\rrojas participo.",
        "citations": ["EVT-0001"],
    }]})
    accepted, rejected = validate_paragraphs(raw, {"hallazgo:F-001": ctx})
    assert not accepted
    assert "rrojas" in rejected[0]["reason"]


def test_validador_rechaza_cifra_no_verificable():
    ctx = _ctx()
    raw = json.dumps({"paragraphs": [{
        "section": "hallazgo:F-001", "label": "Hecho",
        "text": "Se observaron 4242 intentos.", "citations": ["EVT-0001"],
    }]})
    accepted, rejected = validate_paragraphs(raw, {"hallazgo:F-001": ctx})
    assert not accepted
    assert "4242" in rejected[0]["reason"]


def test_validador_rechaza_json_invalido_y_parrafo_sin_citas():
    ctx = _ctx()
    accepted, rejected = validate_paragraphs("esto no es json", {"hallazgo:F-001": ctx})
    assert not accepted and rejected and "JSON" in rejected[0]["reason"]

    raw = json.dumps({"paragraphs": [{
        "section": "hallazgo:F-001", "label": "Hecho", "text": "sin citas", "citations": [],
    }]})
    accepted, rejected = validate_paragraphs(raw, {"hallazgo:F-001": ctx})
    assert not accepted and "citas" in rejected[0]["reason"]


# ---------------------- plantillas deterministas ----------------------

def test_plantilla_hallazgo_sin_evidencia_frase_exacta():
    f = {
        "finding_id": "F-001", "rule_id": "AUTH-001", "rule_name": "Fuerza bruta",
        "category": "Autenticación", "severity": "Alto", "score": 65, "band": "Alto",
        "total_events_matched": 0, "evidence_log_ids": [], "time_range": {"start": None, "end": None},
        "statements": {"hecho": [], "inferencia": [], "hipotesis": []},
        "entities": {}, "mitre": [], "absorbed_detail": None,
    }
    paras = finding_paragraphs(f)
    assert paras and any(p["text"] == NO_EVIDENCE_PHRASE for p in paras)


# ------------------- redaccion end-to-end (proveedor none) -------------------

def test_narrative_sin_generar_responde_404():
    sid, sheet = _analyze_sample()
    r = client.get(f"/api/sessions/{sid}/narrative")
    assert r.status_code == 404


def test_narrative_plantillas_end_to_end():
    sid, sheet = _analyze_sample()
    r = client.post(f"/api/sessions/{sid}/narrative")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mode"] == "plantillas"
    assert body["ai_state"]["used"] is False

    findings = client.get(f"/api/sessions/{sid}/findings").json()["findings"]
    incidents = client.get(f"/api/sessions/{sid}/incidents").json()["incidents"]
    assert body["total_sections"] == 1 + len(findings) + len(incidents)

    sections = {s["section_id"]: s for s in body["sections"]}
    assert "resumen_ejecutivo" in sections
    assert f"hallazgo:{findings[0]['finding_id']}" in sections
    assert f"incidente:{incidents[0]['incident_id']}" in sections

    # Todo parrafo de plantilla procede de plantilla y cita evidencia de su hallazgo.
    for f in findings:
        sec = sections[f"hallazgo:{f['finding_id']}"]
        evid = set(f["evidence_log_ids"])
        for p in sec["paragraphs"]:
            assert p["source"] == "plantilla"
            assert p["label"] in ("Hecho", "Inferencia", "Hipótesis")
            if f["evidence_log_ids"]:
                assert set(p["citations"]) <= evid
        if not f["evidence_log_ids"]:
            assert any(p["text"] == NO_EVIDENCE_PHRASE for p in sec["paragraphs"])

    # GET devuelve la ultima redaccion almacenada.
    r2 = client.get(f"/api/sessions/{sid}/narrative")
    assert r2.status_code == 200 and r2.json()["mode"] == "plantillas"


def test_narrative_ia_invalida_cae_a_plantillas(monkeypatch):
    sid, sheet = _analyze_sample()
    from app.services import sessions as store

    result = store.get_session(sid).analyses[sheet]
    monkeypatch.setattr("app.ai.providers.get_adapter", lambda *a, **k: _fake_adapter("no soy json")())
    n = generate_narrative(result, provider_override="openai_compatible", masking_override=False)
    assert n["ai_state"]["used"] is True
    assert n["ai_state"]["accepted_paragraphs"] == 0
    assert n["ai_state"]["rejected"], "debe registrar el motivo del descarte"
    assert all(p["source"] == "plantilla" for s in n["sections"] for p in s["paragraphs"])


def test_narrative_ia_valida_y_rechazos_selectivos(monkeypatch):
    sid, sheet = _analyze_sample()
    from app.services import sessions as store

    result = store.get_session(sid).analyses[sheet]
    findings = result.detection["findings"]
    target = findings[0]
    section = f"hallazgo:{target['finding_id']}"
    ok_text = (
        f"El hallazgo {target['finding_id']} de la regla {target['rule_id']} cubre "
        f"{target['total_events_matched']} evento(s) con evidencia {target['evidence_log_ids'][0]}."
    )
    bad_paragraph = {
        "section": section, "label": "Hecho", "text": "Inventa la IP 198.51.100.99.",
        "citations": [target["evidence_log_ids"][0]],
    }
    payload = {"paragraphs": [
        {"section": section, "label": "Hecho", "text": ok_text, "citations": [target["evidence_log_ids"][0]]},
        bad_paragraph,
    ]}
    monkeypatch.setattr(
        "app.ai.providers.get_adapter",
        lambda *a, **k: _fake_adapter(json.dumps(payload, ensure_ascii=False))(),
    )
    n = generate_narrative(result, provider_override="openai_compatible", masking_override=False)
    assert n["mode"] == "ia"
    assert n["ai_state"]["accepted_paragraphs"] == 1
    assert len(n["ai_state"]["rejected"]) == 1
    sec = next(s for s in n["sections"] if s["section_id"] == section)
    assert all(p["source"] == "ia_validada" for p in sec["paragraphs"])
    # Las demas secciones conservan la plantilla.
    other = next(s for s in n["sections"] if s["section_id"] != section and s["paragraphs"])
    assert all(p["source"] == "plantilla" for p in other["paragraphs"])
