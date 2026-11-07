# tests/test_detection.py - Fase B: motor determinista.
# Cada regla con caso positivo y negativo en datos sinteticos (PLAN seccion 13);
# integracion con el Excel de ejemplo: absorcion AUTH-001/AUTH-002 y senales esperadas.
from pathlib import Path

import pytest

from app.detection.engine import run_detection
from app.detection.loader import DetectionConfigError, load_rules, load_rules_cached

SAMPLE = Path(__file__).resolve().parents[2] / "data" / "sample" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"


def ev(
    log_id: str,
    ts: str,
    *,
    host: str | None = None,
    user: str | None = None,
    src_ip: str | None = None,
    code: str | None = None,
    desc: str | None = None,
    cmd: str | None = None,
    result: str = "success",
    logon_type: str | None = None,
    dst: str | None = None,
    share: str | None = None,
    bytes_out: int | None = None,
    scope: str = "private",
):
    e = {
        "log_id": log_id,
        "row_number": 1,
        "sheet_name": "s",
        "timestamp_raw": ts,
        "timestamp_parsed": ts,
        "timestamp_status": "valid_wall",
        "host_raw": host,
        "host_key": (host or "").lower().replace("-", "") or None,
        "user_raw": user,
        "user_key": (user or "").lower() or None,
        "event_code": code,
        "event_description": desc,
        "source_ip": src_ip,
        "source_ip_scope": scope if src_ip else None,
        "destination_raw": dst,
        "destination_host": dst,
        "destination_ip": None,
        "destination_port": None,
        "log_source": None,
        "process_command_line": cmd,
        "process_name": (cmd.split()[0] if cmd else None),
        "parent_process": None,
        "result_raw": result,
        "result_norm": result,
        "severity_siem": None,
        "logon_type": logon_type,
        "http_method": None,
        "http_status": None,
        "url_path": None,
        "share": share,
        "file_path": None,
        "bytes_out": bytes_out,
        "task_name": None,
        "service_name": None,
        "extracted": {},
        "raw": {},
        "quality_flags": [],
    }
    return e


# ---------------- loader ----------------

def test_loader_carga_29_reglas_validas():
    rules = load_rules()
    ids = {r.id for r in rules}
    esperadas = {
        "AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "AUTH-005", "AUTH-007",
        "PRIV-001", "PRIV-002",
        "EXEC-001", "EXEC-002", "EXEC-003", "EXEC-004", "EXEC-005", "EXEC-006", "EXEC-007",
        "PERS-001", "PERS-002", "PERS-003",
        "LAT-001", "LAT-002", "LAT-003", "LAT-004",
        "EXF-001", "EXF-002", "EXF-003", "EXF-004",
        "WEB-001", "WEB-002", "WEB-003",
    }
    assert ids == esperadas
    severidades = {r.base_severity for r in rules}
    assert severidades <= {"Bajo", "Medio", "Alto", "Crítico"}
    # EXEC-004 y WEB-003 son criticos desde la base (PLAN 7.1)
    por_id = {r.id: r for r in rules}
    assert por_id["EXEC-004"].base_severity == "Crítico"
    assert por_id["WEB-003"].base_severity == "Crítico"


def test_loader_detecta_yaml_invalido(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  - id: X-001\n    name: n\n    category: c\n    description: d\n    rationale: r\n    base_severity: Ultra\n", encoding="utf-8")
    with pytest.raises(DetectionConfigError):
        load_rules(bad)


def test_loader_detecta_id_duplicada(tmp_path):
    base = (
        "id: {rid}\n    name: n\n    category: c\n    description: d\n    rationale: r\n"
        "    base_severity: Medio\n"
    )
    dup = tmp_path / "dup.yaml"
    dup.write_text("rules:\n  - " + base.format(rid="X-001") + "  - " + base.format(rid="X-001"), encoding="utf-8")
    with pytest.raises(DetectionConfigError):
        load_rules(dup)


def test_cache_reglas_consistente():
    a = load_rules_cached(None)
    b = load_rules_cached(None)
    assert a is b  # mismo objeto en cache


# ---------------- casos sinteticos por regla ----------------

def _only_rule(events, rule_id):
    out = run_detection(events, rules_path=None)
    findings = [f for f in out["findings"] if f["rule_id"] == rule_id]
    cov = {c["rule_id"]: c for c in out["coverage"]}[rule_id]
    return findings, cov


def test_auth001_positivo_y_negativo():
    pos = [
        ev(f"L{i}", f"2026-01-01 10:00:{i:02d}", user="CORP\\ana", src_ip="203.0.113.9", code="4625", result="failure")
        for i in range(6)
    ]
    findings, cov = _only_rule(pos, "AUTH-001")
    assert cov["status"] == "executed" and len(findings) == 1
    assert findings[0]["total_events_matched"] == 6
    assert all(f["evidence_log_ids"] for f in findings)

    # negativo: 3 fallos aislados (bajo el umbral) no generan hallazgo
    neg = pos[:3]
    findings2, cov2 = _only_rule(neg, "AUTH-001")
    assert cov2["status"] == "executed_no_findings" and not findings2


def test_auth002_spray_positivo():
    usuarios = [f"CORP\\u{i}" for i in range(6)]
    events = [
        ev(f"S{i:02d}", f"2026-01-01 12:{i:02d}:00", user=usuarios[i], src_ip="198.51.100.5", code="4625", result="failure", scope="public")
        for i in range(6)
    ]
    findings, cov = _only_rule(events, "AUTH-002")
    assert cov["status"] == "executed" and len(findings) == 1
    assert findings[0]["total_events_matched"] == 6
    assert "origen_publico" in findings[0]["factors"]


def test_auth003_exito_tras_fallos():
    base = [
        ev(f"A{i}", f"2026-01-01 09:{i:02d}:00", user="CORP\\victima", src_ip="203.0.113.10", code="4625", result="failure", scope="public")
        for i in range(4)
    ]
    ok = ev("OK1", "2026-01-01 09:10:00", user="CORP\\victima", src_ip="203.0.113.10", code="4624", result="success", scope="public")
    findings, cov = _only_rule(base + [ok], "AUTH-003")
    assert cov["status"] == "executed" and len(findings) == 1
    assert findings[0]["evidence_log_ids"][0] == "OK1"


def test_auth005_rdp_fallos_previos():
    events = [
        ev("R1", "2026-01-01 08:00:00", host="SRV-A", user="CORP\\admin", src_ip="203.0.113.3", code="4625", result="failure", logon_type="10", scope="public"),
        ev("R2", "2026-01-01 08:01:00", host="SRV-A", user="CORP\\admin", src_ip="203.0.113.3", code="4625", result="failure", logon_type="10", scope="public"),
        ev("R3", "2026-01-01 08:02:00", host="SRV-A", user="CORP\\admin", src_ip="203.0.113.3", code="4624", result="success", logon_type="10", scope="public"),
    ]
    findings, cov = _only_rule(events, "AUTH-005")
    assert cov["status"] == "executed" and len(findings) == 1


def test_priv002_4672_publico():
    pos = [ev("P1", "2026-01-01 07:00:00", user="CORP\\x", src_ip="203.0.113.99", code="4672", result="success", scope="public")]
    findings, cov = _only_rule(pos, "PRIV-002")
    assert cov["status"] == "executed" and len(findings) == 1
    # negativo: 4672 con origen interno no dispara
    neg = [ev("P2", "2026-01-01 07:00:00", user="CORP\\x", src_ip="10.10.1.5", code="4672", result="success")]
    findings2, cov2 = _only_rule(neg, "PRIV-002")
    assert cov2["status"] == "executed_no_findings" and not findings2


def test_exec001_encoded_powershell():
    pos = [ev("E1", "2026-01-01 06:00:00", user="CORP\\x", host="WS-1", cmd="powershell.exe -NoProfile -EncodedCommand AAAA")]
    findings, cov = _only_rule(pos, "EXEC-001")
    assert cov["status"] == "executed" and len(findings) == 1
    neg = [ev("E2", "2026-01-01 06:00:00", user="CORP\\x", host="WS-1", cmd="notepad.exe")]
    findings2, cov2 = _only_rule(neg, "EXEC-001")
    assert cov2["status"] == "executed_no_findings" and not findings2


def test_exec004_vssadmin_es_critico():
    pos = [ev("V1", "2026-01-01 05:00:00", user="CORP\\x", host="WS-1", cmd="vssadmin.exe delete shadows /all /quiet")]
    findings, cov = _only_rule(pos, "EXEC-004")
    assert cov["status"] == "executed" and len(findings) == 1
    assert findings[0]["severity"] == "Crítico"


def test_exec005_staging():
    pos = [ev("T1", "2026-01-01 04:00:00", user="CORP\\x", host="WS-1", cmd="tar.exe -a -c -f C:\\Temp\\datos.zip C:\\Legal\\informes")]
    findings, cov = _only_rule(pos, "EXEC-005")
    assert cov["status"] == "executed" and len(findings) == 1


def test_exec006_binario_ruta_no_estandar():
    pos = [ev("B1", "2026-01-01 03:00:00", user="CORP\\x", host="WS-1", cmd="C:\\ProgramData\\tool.exe")]
    findings, cov = _only_rule(pos, "EXEC-006")
    assert cov["status"] == "executed" and len(findings) == 1
    neg = [ev("B2", "2026-01-01 03:00:00", user="CORP\\x", host="WS-1", cmd="C:\\Windows\\System32\\cmd.exe /c dir")]
    findings2, cov2 = _only_rule(neg, "EXEC-006")
    assert cov2["status"] == "executed_no_findings" and not findings2


def test_pers001_pers002_por_codigo():
    pos = [ev("Q1", "2026-01-01 02:00:00", user="CORP\\x", host="SRV", code="4698", desc="A scheduled task was created"),
           ev("Q2", "2026-01-01 02:01:00", user="CORP\\x", host="SRV", code="7045", desc="A service was installed in the system")]
    f1, c1 = _only_rule(pos, "PERS-001")
    f2, c2 = _only_rule(pos, "PERS-002")
    assert len(f1) == 1 and len(f2) == 1
    # negativo: eventos 7036 (servicio corriendo) no son instalacion
    neg = [ev("Q3", "2026-01-01 02:00:00", user="CORP\\x", host="SRV", code="7036", desc="Service entered running state")]
    f1n, c1n = _only_rule(neg, "PERS-001")
    f2n, c2n = _only_rule(neg, "PERS-002")
    assert not f1n and not f2n


def test_pers003_beaconing():
    cmds = [ev(f"W{i}", f"2026-01-01 11:{i*5:02d}:00", user="CORP\\y", host="SRV", code="4688", cmd="C:\\ProgramData\\wuhelper.exe") for i in range(5)]
    findings, cov = _only_rule(cmds, "PERS-003")
    assert cov["status"] == "executed" and len(findings) == 1
    # negativo: intervalos demasiado largos
    far = [ev(f"Z{i}", f"2026-01-0{i+1} 11:00:00", user="CORP\\y", host="SRV", code="4688", cmd="C:\\ProgramData\\wuhelper.exe") for i in range(5)]
    f2, c2 = _only_rule(far, "PERS-003")
    assert not f2


def test_exf002_post_repetidos_y_volumen():
    pos = [
        ev(f"X{i}", f"2026-01-01 14:{i:02d}:00", user="CORP\\y", host="WS-1", dst="198.51.100.88:443",
           desc="HTTPS POST outbound", bytes_out=10_000_000)
        for i in range(5)
    ]
    findings, cov = _only_rule(pos, "EXF-002")
    assert cov["status"] == "executed" and len(findings) == 1
    assert findings[0]["total_events_matched"] == 5
    # negativo: pocos posts con poco volumen
    neg = pos[:2]
    f2, c2 = _only_rule(neg, "EXF-002")
    assert not f2


def test_exf004_lectura_masiva():
    pos = [
        ev(f"D{i:02d}", f"2026-01-01 15:{i:02d}:00", user="CORP\\svc", host="FS", code="4663",
           cmd=f"File access: Finance\\FY2026\\doc{i:03d}.xlsx", dst="\\\\FS\\Finance")
        for i in range(12)
    ]
    findings, cov = _only_rule(pos, "EXF-004")
    assert cov["status"] == "executed" and len(findings) == 1
    # negativo: pocas lecturas
    f2, c2 = _only_rule(pos[:4], "EXF-004")
    assert not f2


def test_web001_rafaga_errores():
    pos = [
        ev(f"H{i:02d}", f"2026-01-01 16:{i:02d}:00", host="WEB", src_ip="192.0.2.9", dst="WEB:443", code="HTTP_ACCESS", result="404", scope="public")
        for i in range(12)
    ]
    for i, e in enumerate(pos):
        e["http_status"] = 404
    findings, cov = _only_rule(pos, "WEB-001")
    assert cov["status"] == "executed" and len(findings) == 1
    # negativo: pocos errores
    f2, c2 = _only_rule(pos[:5], "WEB-001")
    assert not f2


def test_web003_webshell_cmd_en_url_y_pool():
    pos = [
        ev("U1", "2026-01-01 17:00:00", host="WEB", src_ip="192.0.2.9", dst="WEB:443", code="HTTP_ACCESS", result="200", scope="public"),
        ev("U2", "2026-01-01 17:01:00", host="WEB", src_ip="192.0.2.9", code="4688", result="success",
           user="IIS APPPOOL\\DefaultAppPool", cmd="cmd.exe /c whoami"),
    ]
    pos[0]["process_command_line"] = "/uploads/test.aspx?cmd=whoami"  # URL en columna de comando
    findings, cov = _only_rule(pos, "WEB-003")
    assert cov["status"] == "executed" and len(findings) == 1
    assert findings[0]["severity"] == "Crítico"
    # negativo: peticion normal sin comandos
    normal = ev("U3", "2026-01-01 17:00:00", host="WEB", src_ip="192.0.2.9", dst="WEB:443", code="HTTP_ACCESS", result="200", scope="public")
    normal["process_command_line"] = "/index.html"
    f2, c2 = _only_rule([normal], "WEB-003")
    assert not f2


def test_lat001_requiere_ancla_externa():
    # positivo: ancla publica y reaparicion en otro host (logon type 3)
    pos = [
        ev("LA1", "2026-01-01 18:00:00", host="SRV-A", user="CORP\\admin", src_ip="203.0.113.4", code="4624", result="success", scope="public"),
        ev("LA2", "2026-01-01 18:10:00", host="SRV-B", user="CORP\\admin", src_ip="10.10.2.15", code="4624", result="success", logon_type="3"),
    ]
    findings, cov = _only_rule(pos, "LAT-001")
    assert cov["status"] == "executed" and len(findings) == 1
    # negativo: mismo patron sin ancla externa no genera hallazgo (ruido interno)
    neg = [
        ev("LB1", "2026-01-01 18:00:00", host="SRV-A", user="CORP\\laura", src_ip="10.10.1.9", code="4624", result="success"),
        ev("LB2", "2026-01-01 18:10:00", host="SRV-B", user="CORP\\laura", src_ip="10.10.2.15", code="4624", result="success", logon_type="3"),
    ]
    f2, c2 = _only_rule(neg, "LAT-001")
    assert not f2


def test_lat003_requiere_dos_saltos():
    ancla = ev("C0", "2026-01-01 19:00:00", host="SRV-A", user="CORP\\admin", src_ip="203.0.113.4", code="4624", result="success", scope="public")
    salto1 = ev("C1", "2026-01-01 19:05:00", host="SRV-B", user="CORP\\admin", code="4624", result="success", logon_type="3")
    # un solo salto: no genera hallazgo (LAT-003), solo LAT-001
    f1, c1 = _only_rule([ancla, salto1], "LAT-003")
    assert not f1
    salto2 = ev("C2", "2026-01-01 19:10:00", host="SRV-C", user="CORP\\admin", code="4624", result="success", logon_type="3")
    f2, c2 = _only_rule([ancla, salto1, salto2], "LAT-003")
    assert len(f2) == 1


def test_lat004_insufficient_data():
    findings, cov = _only_rule([ev("M1", "2026-01-01 20:00:00", src_ip="10.10.1.1", dst="198.51.100.9")], "LAT-004")
    assert cov["status"] == "insufficient_data" and not findings


def test_cobertura_regla_deshabilitada(tmp_path):
    yaml_txt = (
        "rules:\n"
        "  - id: AUTH-001\n    name: Fuerza bruta por usuario/IP\n    category: Autenticación\n"
        "    description: d\n    rationale: r\n    base_severity: Alto\n    enabled: false\n"
        "    required_fields: [ts, result, user]\n    parameters: {min_failures: 5, window_minutes: 15}\n"
        "    mitre: [T1110.001]\n    evidence_limit: 12\n    use_probable_aliases: true\n"
    )
    path = tmp_path / "rules.yaml"
    path.write_text(yaml_txt, encoding="utf-8")
    events = [
        ev(f"L{i}", f"2026-01-01 10:00:{i:02d}", user="CORP\\ana", src_ip="203.0.113.9", code="4625", result="failure")
        for i in range(6)
    ]
    out = run_detection(events, rules_path=str(path))
    cov = {c["rule_id"]: c for c in out["coverage"]}
    assert cov["AUTH-001"]["status"] == "skipped_disabled"


def test_cobertura_regla_sin_campos():
    out = run_detection([ev("N1", "2026-01-01 21:00:00", host="WS-1")], rules_path=None)
    cov = {c["rule_id"]: c for c in out["coverage"]}
    assert cov["AUTH-001"]["status"] == "skipped_missing_fields"


def test_todos_los_hallazgos_tienen_evidencia_y_afirmaciones():
    events = _load_sample_events()
    out = run_detection(events)
    for f in out["findings"]:
        assert f["evidence_log_ids"], f"Hallazgo sin evidencia: {f['finding_id']}"
        assert f["statements"]["hecho"], "Todo hallazgo necesita al menos un 'Hecho'"
        assert f["total_evidence"] == f["total_events_matched"]
        ids_conocidos = {e["log_id"] for e in events}
        assert set(f["evidence_log_ids"]) <= ids_conocidos, "Evidencia debe ser de eventos reales"


def _load_sample_events():
    import io

    from fastapi.testclient import TestClient

    from app.main import app

    client = TestClient(app)
    r = client.post("/api/upload", files={"file": ("logs.xlsx", SAMPLE.read_bytes(), "application/octet-stream")})
    body = r.json()
    sid = body["session_id"]
    sheet = body["sheets"][0]["name"]
    mapping = [{"column": s["column"], "field": s["field"]} for s in body["mappings"][0]["suggestions"]]
    r2 = client.post(
        f"/api/sessions/{sid}/analyze",
        json={"sheet": sheet, "header_row": body["sheets"][0]["header_row"], "mapping": mapping},
    )
    assert r2.status_code == 200, r2.text
    import app.services.sessions as store

    events = store.get_session(sid).analyses[sheet].events
    client.delete(f"/api/sessions/{sid}")
    return events


# ---------------- integracion contra el Excel (6 cadenas, PLAN 14) ----------------

@pytest.fixture(scope="module")
def sample_detection():
    events = _load_sample_events()
    return run_detection(events)


def test_total_hallazgos_en_rango_25_50(sample_detection):
    total = sample_detection["summary"]["total_findings"]
    assert 25 <= total <= 50, f"Total {total} fuera del rango 25-50 (PLAN 6.3)"


def test_sin_errores_de_cobertura(sample_detection):
    cov = sample_detection["coverage"]
    errores = [c for c in cov if c["status"] == "error"]
    assert not errores, f"Reglas con error: {[(c['rule_id'], c.get('reason')) for c in errores]}"


def test_spray_absorbido_en_auth002(sample_detection):
    findings = sample_detection["findings"]
    auth002 = [f for f in findings if f["rule_id"] == "AUTH-002"]
    auth001 = [f for f in findings if f["rule_id"] == "AUTH-001"]
    assert len(auth002) == 1, "El spraying debe generar exactamente 1 hallazgo"
    assert auth002[0]["total_events_matched"] == 33, "El spray del ejemplo tiene 33 fallos"
    assert not auth001, "Los fallos del spray se absorben en AUTH-002; AUTH-001 no debe duplicar"


def test_cadenas_2_a_6_detectadas(sample_detection):
    findings = sample_detection["findings"]
    reglas = {f["rule_id"] for f in findings}
    # Cadena 2: RDP admin + lateral
    assert "AUTH-005" in reglas and "LAT-001" in reglas
    lat001 = next(f for f in findings if f["rule_id"] == "LAT-001")
    assert "EVT-00188" in lat001["evidence_log_ids"], "LAT-001 debe anclarse al exito externo del admin"
    # Cadena 3: backup/Finance + vssadmin
    assert "EXEC-004" in reglas, "vssadmin debe detectarse (EXEC-004)"
    exec004 = next(f for f in findings if f["rule_id"] == "EXEC-004")
    assert "EVT-00314" in exec004["evidence_log_ids"]
    exf004 = next(f for f in findings if f["rule_id"] == "EXF-004")
    assert exf004["total_events_matched"] == 16, "16 lecturas de documentos Finance (EVT-00284..309)"
    assert any(
        "EVT-00280" in f["evidence_log_ids"] for f in findings if f["rule_id"] == "EXEC-001"
    ), "PowerShell encoded de backupsvc debe detectarse (EVT-00280)"
    # Cadena 4: Legal + exfiltracion
    exf002 = next(f for f in findings if f["rule_id"] == "EXF-002")
    assert exf002["total_events_matched"] == 22, "22 POSTs salientes"
    assert any(
        "EVT-00428" in f["evidence_log_ids"] for f in findings if f["rule_id"] == "EXEC-005"
    ), "7z sobre C:\\Legal debe detectarse (EVT-00428)"
    # Cadena 5: persistencia helpdesk
    assert "PERS-001" in reglas and "PERS-002" in reglas
    pers001 = next(f for f in findings if f["rule_id"] == "PERS-001")
    assert "EVT-00523" in pers001["evidence_log_ids"]
    # Cadena 6: ataque web
    web003 = next(f for f in findings if f["rule_id"] == "WEB-003")
    assert "EVT-00599" in web003["evidence_log_ids"]
    assert "EVT-00573" in next(f for f in findings if f["rule_id"] == "WEB-001")["evidence_log_ids"], \
        "La rafaga de errores HTTP debe incluir la primera respuesta 404 (EVT-00573)"


def test_exito_tras_fallos_mgarcia(sample_detection):
    auth003 = [f for f in sample_detection["findings"] if f["rule_id"] == "AUTH-003"]
    assert any("EVT-00123" in f["evidence_log_ids"] for f in auth003), "Exito de mgarcia tras el spray"
    assert any("EVT-00188" in f["evidence_log_ids"] for f in auth003), "Exito RDP del admin tras fallos"


def test_sin_hallazgos_de_cuentas_benignas_aisladas(sample_detection):
    """Cuentas benignas con actividad normal no generan hallazgos de autenticacion
    propios ni aparecen como unicas entidades de hallazgos (PLAN 6.3)."""
    benignas = {"corp\\mruiz", "corp\\jlopez", "corp\\dtorres"}
    findings = sample_detection["findings"]
    # No debe existir ningun hallazgo de AUTH-001 (absorcion del spray correcta)
    assert not [f for f in findings if f["rule_id"] == "AUTH-001"]
    # Las victimas del spray legítimamente aparecen en AUTH-002, pero ninguna cuenta
    # benigna debe ser la unica entidad de un hallazgo de autenticacion.
    for f in findings:
        if f["rule_id"] in ("AUTH-005", "AUTH-007"):
            usuarios = {u.casefold() for u in f["entities"]["users"]}
            assert usuarios - benignas, f"Hallazgo {f['finding_id']} solo con cuentas benignas: {usuarios}"


def test_resumen_severidades(sample_detection):
    resumen = sample_detection["summary"]["findings_by_severity"]
    assert resumen.get("Crítico", 0) >= 2, "EXEC-004 y WEB-003 son criticos"
    assert resumen.get("Alto", 0) >= 5
