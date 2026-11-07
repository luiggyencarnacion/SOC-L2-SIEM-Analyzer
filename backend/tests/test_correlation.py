# tests/test_correlation.py - Fase C: scoring, correlacion, incidentes, relaciones y override.
# Unitarios con hallazgos sinteticos + integracion con el Excel de ejemplo (sin hardcodear
# senales: lo que se comprueba del ejemplo es el NUMERO de cadenas del PLAN, 6, y estructura).
import io
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.correlation import correlator
from app.correlation.loader import CorrelationConfigError, load_config, load_config_cached
from app.correlation.scoring import band_for, score_findings
from app.main import app

client = TestClient(app)

SAMPLE = Path(__file__).resolve().parents[2] / "data" / "sample" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"


def _cfg() -> "correlator.CorrelationConfig":
    return load_config_cached()


# ------------------------- helpers de hallazgos sinteticos -------------------------

def make_finding(
    fid: str,
    rule_id: str = "EXEC-002",
    category: str = "Ejecución",
    severity: str = "Medio",
    users=(),
    hosts=(),
    ips=(),
    destinations=(),
    start: str | None = "2026-01-01T10:00:00",
    end: str | None = "2026-01-01T10:05:00",
    factors=(),
    evidence=(),
    mitre=(),
) -> dict:
    return {
        "finding_id": fid,
        "rule_id": rule_id,
        "rule_name": f"regla {rule_id}",
        "category": category,
        "severity": severity,
        "entities": {
            "users": list(users),
            "hosts": list(hosts),
            "source_ips": list(ips),
            "destinations": list(destinations),
        },
        "evidence_log_ids": list(evidence),
        "time_range": {"start": start, "end": end},
        "factors": list(factors),
        "mitre": list(mitre),
    }


# ---------------------------------- config ----------------------------------

def test_config_valida_por_defecto():
    cfg = load_config()
    assert cfg.window_minutes == 90
    assert cfg.base_scores["Bajo"] == 20
    assert cfg.factors_cap == 30


def test_config_invalida_falla_rapido(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("window_minutes: -5\nscoring: {}\n", encoding="utf-8")
    with pytest.raises(CorrelationConfigError):
        load_config(bad)


# ---------------------------------- scoring ----------------------------------

def test_scoring_invariante_base_banda():
    """PLAN 7.1: base_severity X sin factores cae exactamente en la banda X."""
    cfg = load_config()
    for sev, expected in (("Bajo", 20), ("Medio", 45), ("Alto", 65), ("Crítico", 85)):
        f = make_finding("F-001", severity=sev)
        score_findings([f], cfg)
        assert f["score"] == expected
        assert f["band"] == sev


def test_scoring_factor_origen_publico_y_cap():
    cfg = load_config()
    f = make_finding("F-001", severity="Bajo", factors=["origen_publico"])
    score_findings([f], cfg)
    assert f["score"] == 25  # 20 + 5
    assert f["band"] == "Bajo"

    # Tope +30: acumular muchos factores no puede pasar de base + 30.
    many = make_finding(
        "F-002",
        severity="Bajo",
        users=["svc_backup"],
        hosts=[f"HOST-{i:02d}" for i in range(5)],  # multi_host + activo si casa patron
        factors=["origen_publico", "acceso_a_datos_sensibles", "volumen_grande", "explotacion_web"],
        rule_id="EXEC-004",  # evasion
        category="Persistencia",  # persistencia
    )
    score_findings([many], cfg)
    assert many["factors_points"]["applied"] <= cfg.factors_cap
    assert many["score"] == min(100, cfg.base_scores["Bajo"] + cfg.factors_cap)


def test_scoring_contexto_privilegiado_patrones():
    cfg = load_config()
    f = make_finding("F-001", users=["CORP\\svc_backup"])
    score_findings([f], cfg)
    factors = {x["factor"] for x in f["factors_applied"]}
    assert "contexto_privilegiado" in factors


def test_band_for_fuera_de_rango_no_explota():
    cfg = load_config()
    assert band_for(0, cfg) == "Bajo"
    assert band_for(100, cfg) == "Crítico"


# ------------------------------- correlacion --------------------------------

def test_correlacion_agrupa_por_usuario_compartido():
    cfg = load_config()
    f1 = make_finding("F-001", users=["CORP\\admin"], ips=["203.0.113.9"])
    f2 = make_finding("F-002", rule_id="EXEC-004", users=["admin"], start="2026-01-01T10:20:00", end="2026-01-01T10:25:00")
    out = correlator.run_correlation([f1, f2], [], cfg)
    assert out["summary"]["total_incidents"] == 1
    assert out["incidents"][0]["findings"] == ["F-001", "F-002"]
    assert out["incidents"][0]["grouping"]["max_gap_minutes"] is not None


def test_correlacion_nunca_agrupa_solo_por_host():
    """PLAN 6.4: mismo servidor, cuentas y horarios distintos -> cadenas independientes
    y relacion cruzada 'mismo activo'."""
    cfg = load_config()
    f1 = make_finding("F-001", users=["uana"], hosts=["SERV-A"], start="2026-01-01T10:00:00", end="2026-01-01T10:05:00")
    f2 = make_finding("F-002", users=["otro"], hosts=["SERV-A"], start="2026-01-01T10:10:00", end="2026-01-01T10:15:00")
    out = correlator.run_correlation([f1, f2], [], cfg)
    assert out["summary"]["total_incidents"] == 2
    assert out["relations"], "debe existir la relacion 'mismo activo'"
    rel = out["relations"][0]
    assert rel["incidents"] == ["I-001", "I-002"]
    assert rel["shared_hosts"] == ["SERV-A"]
    assert "mismo activo" in rel["conclusion"]


def test_correlacion_respetando_ventana_temporal():
    cfg = load_config()
    # Usuario compartido, pero a 3 horas de distancia: fuera de la ventana de 90 min.
    f1 = make_finding("F-001", users=["mgomez"], start="2026-01-01T08:00:00", end="2026-01-01T08:10:00")
    f2 = make_finding("F-002", users=["mgomez"], start="2026-01-01T11:30:00", end="2026-01-01T11:35:00")
    out = correlator.run_correlation([f1, f2], [], cfg)
    assert out["summary"]["total_incidents"] == 2
    assert out["relations"] == []  # ni host comparten


def test_correlacion_alias_genera_nota_inferencia():
    """Misma clave canonica con valores crudos distintos -> nota de inferencia."""
    cfg = load_config()
    f1 = make_finding("F-001", hosts=["DC-01"], users=["CORP\\userone"], ips=["198.51.100.7"])
    f2 = make_finding("F-002", hosts=["DC01"], users=["userone"], ips=["198.51.100.7"])
    out = correlator.run_correlation([f1, f2], [], cfg)
    assert out["summary"]["total_incidents"] == 1
    assert any("inferencia" in n for n in out["incidents"][0]["grouping"]["alias_notes"])


def test_incidente_score_y_fases_observadas():
    cfg = load_config()
    f1 = make_finding("F-001", rule_id="AUTH-004", category="Autenticación", severity="Alto", users=["uana"], ips=["203.0.113.9"])
    f2 = make_finding("F-002", rule_id="EXEC-003", category="Ejecución", severity="Crítico", users=["uana"], start="2026-01-01T10:30:00", end="2026-01-01T10:35:00")
    f3 = make_finding("F-003", rule_id="EXF-002", category="Exfiltración", severity="Alto", users=["uana"], start="2026-01-01T11:00:00", end="2026-01-01T11:05:00")
    members = [f1, f2, f3]
    score_findings(members, cfg)
    out = correlator.run_correlation(members, [], cfg)
    assert out["summary"]["total_incidents"] == 1
    inc = out["incidents"][0]
    # Max hallazgo = 85 (Critico); 3 fases observadas -> bonus 2*5=10.
    assert inc["max_finding_score"] == 85
    assert inc["incident_bonus"] == 10
    assert inc["score"] == 95
    assert inc["band"] == "Crítico"
    assert inc["kill_chain_phases"] == ["Acceso inicial", "Ejecución", "Exfiltración"]
    # Bonus con tope: aunque haya muchas fases, el bonus no pasa del tope.


def test_incidente_bonus_tope_15():
    cfg = load_config()
    members = []
    rule_ids = [("AUTH-004", "Autenticación"), ("EXEC-006", "Ejecución"), ("PERS-001", "Persistencia"),
                ("LAT-001", "Movimiento lateral"), ("EXF-001", "Exfiltración")]
    t0 = datetime(2026, 1, 1, 10, 0, 0)
    for n, (rid, cat) in enumerate(rule_ids):
        members.append(make_finding(
            f"F-{n+1:03d}", rule_id=rid, category=cat, severity="Alto", users=["uana"],
            start=(t0 + timedelta(minutes=10 * n)).isoformat(),
            end=(t0 + timedelta(minutes=10 * n + 5)).isoformat(),
        ))
    out = correlator.run_correlation(score_findings(members, cfg), [], cfg)
    inc = out["incidents"][0]
    assert inc["incident_bonus"] == cfg.incident_bonus_cap
    assert inc["score"] == min(100, 65 + cfg.incident_bonus_cap)


def test_iocs_extraidos_de_evidencia():
    cfg = load_config()
    f = make_finding(
        "F-001", rule_id="EXF-001", category="Exfiltración", severity="Alto",
        users=["CORP\\ulegal"], evidence=["E-1", "E-2"],
    )
    events = [
        {"log_id": "E-1", "source_ip": "198.51.100.7", "source_ip_scope": "public",
         "destination_ip": "203.0.113.50", "destination_scope": "public",
         "user_raw": "CORP\\ulegal", "url_path": "/upload.php", "destination_host": "drop.example.test"},
        {"log_id": "E-2", "task_name": "TareaX", "file_path": "\\\\SERV\\c$\\x.txt", "share": "\\\\SERV\\finance"},
    ]
    out = correlator.run_correlation([f], events, cfg)
    iocs = out["incidents"][0]["iocs"]
    assert iocs["ips"] == ["198.51.100.7", "203.0.113.50"]
    assert any("/upload.php" in u for u in iocs["urls"])
    assert "TareaX" in iocs["services_tasks"]
    assert "\\\\SERV\\finance" in iocs["shares"]
    assert "ulegal" in iocs["accounts"][0].split("\\")[-1]


def test_sin_hallazgos_devuelve_estructura_vacia():
    cfg = load_config()
    out = correlator.run_correlation([], [], cfg)
    assert out["incidents"] == [] and out["summary"]["total_incidents"] == 0


# --------------------- integracion con el Excel de ejemplo ---------------------

def _upload_and_analyze():
    data = SAMPLE.read_bytes()
    r = client.post("/api/upload", files={"file": ("logs.xlsx", data, "application/octet-stream")})
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


def test_integracion_excel_produce_6_cadenas():
    """Criterio de la fase C: el ejemplo con la config por defecto produce 6 cadenas."""
    sid, _ = _upload_and_analyze()
    r = client.get(f"/api/sessions/{sid}/incidents")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["summary"]["total_incidents"] == 6, [
        (i["incident_id"], i["title"], i["findings"]) for i in body["incidents"]
    ]
    assert body["summary"]["findings_assigned"] == body["summary"]["total_findings"]


def test_integracion_incidentes_estructura_completa():
    sid, _ = _upload_and_analyze()
    body = client.get(f"/api/sessions/{sid}/incidents").json()
    for inc in body["incidents"]:
        assert inc["timeline"], "todo incidente debe tener timeline con evidencia"
        assert inc["score"] >= 0 and inc["band"]
        assert inc["assets"] and isinstance(inc["iocs"], dict)
        assert inc["kill_chain_phases"], "las fases observadas no deben inventarse ni faltar"
        assert inc["grouping"]["justification"]
    # Los scores de incidente caen en bandas coherentes.
    for inc in body["incidents"]:
        bands = {"Bajo": (0, 39), "Medio": (40, 59), "Alto": (60, 79), "Crítico": (80, 100)}
        lo, hi = bands[inc["band"]]
        assert lo <= inc["score"] <= hi


def test_override_manual_de_incidente():
    sid, _ = _upload_and_analyze()
    incidents = client.get(f"/api/sessions/{sid}/incidents").json()["incidents"]
    target = incidents[0]["incident_id"]
    auto_score = incidents[0]["score"]

    # Motivo obligatorio: cadena vacia la rechaza pydantic y solo espacios el endpoint.
    r = client.post(f"/api/sessions/{sid}/overrides", json={
        "target_type": "incident", "target_id": target, "classification": "Falso positivo", "reason": "",
    })
    assert r.status_code == 422
    r = client.post(f"/api/sessions/{sid}/overrides", json={
        "target_type": "incident", "target_id": target, "classification": "Falso positivo", "reason": "  ",
    })
    assert r.status_code == 400

    r = client.post(f"/api/sessions/{sid}/overrides", json={
        "target_type": "incident", "target_id": target,
        "classification": "Falso positivo", "reason": "Verificado con el dueño del activo: mantenimiento planificado.",
    })
    assert r.status_code == 200, r.text

    body = client.get(f"/api/sessions/{sid}/incidents").json()
    inc = next(i for i in body["incidents"] if i["incident_id"] == target)
    assert inc["override"]["classification"] == "Falso positivo"
    assert inc["override"]["reason"].startswith("Verificado")
    assert inc["score"] == auto_score, "el score automatico se conserva"


def test_override_valida_clasificacion_y_objetivo():
    sid, _ = _upload_and_analyze()
    r = client.post(f"/api/sessions/{sid}/overrides", json={
        "target_type": "incident", "target_id": "I-999", "classification": "Alto", "reason": "prueba",
    })
    assert r.status_code == 404
    r = client.post(f"/api/sessions/{sid}/overrides", json={
        "target_type": "incident", "target_id": "I-001", "classification": "Alto", "reason": "prueba",
    })
    assert r.status_code == 200
    r = client.post(f"/api/sessions/{sid}/overrides", json={
        "target_type": "incident", "target_id": "I-001", "classification": "Ultra", "reason": "prueba",
    })
    assert r.status_code == 400
    r = client.post(f"/api/sessions/{sid}/overrides", json={
        "target_type": "cadena", "target_id": "I-001", "classification": "Alto", "reason": "prueba",
    })
    assert r.status_code == 400


def test_override_de_hallazgo_reflejado_en_findings():
    sid, _ = _upload_and_analyze()
    findings = client.get(f"/api/sessions/{sid}/findings").json()["findings"]
    target = findings[0]["finding_id"]
    r = client.post(f"/api/sessions/{sid}/overrides", json={
        "target_type": "finding", "target_id": target, "classification": "Bajo", "reason": "Revisado: scan interno autorizado.",
    })
    assert r.status_code == 200
    f = next(x for x in client.get(f"/api/sessions/{sid}/findings").json()["findings"] if x["finding_id"] == target)
    assert f["override"]["classification"] == "Bajo"
    # El score automatico sigue presente.
    assert isinstance(f["score"], int) and f["band"]
