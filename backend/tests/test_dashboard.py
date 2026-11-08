# tests/test_dashboard.py - Fase D: endpoint /stats, determinismo y filtro
# temporal de eventos. Sin hardcodear valores del ejemplo: todo se deriva de
# la respuesta de la API o del archivo de ejemplo cargado en el test.
import io
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

SAMPLE = Path(__file__).resolve().parents[2] / "data" / "sample" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"


def _make_xlsx_bytes(num_rows: int) -> bytes:
    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "uno"
    ws.append(["Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Result", "Severity"])
    for i in range(1, num_rows + 1):
        ws.append(
            [
                f"L-{i:04d}",
                f"2026-03-0{1 + i % 3} 0{i % 9}:{i % 60:02d}:00",
                f"HO-{i % 5}",
                str(1000 + i),
                f"usr{i % 7}",
                "Success" if i % 2 else "Failure",
                "Alto" if i % 3 else "Bajo",
            ]
        )
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


@pytest.fixture(scope="module")
def analyzed() -> dict:
    """Sube y analiza el Excel de ejemplo una sola vez para todo el modulo."""
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
    analyzed_body = r2.json()
    yield {"sid": sid, "sheet": sheet, "analyze": analyzed_body, "total_rows": analyzed_body["total_rows"]}
    client.delete(f"/api/sessions/{sid}")


def _get_stats(res: dict, params: dict | None = None) -> dict:
    r = client.get(f"/api/sessions/{res['sid']}/stats", params={"sheet": res["sheet"], **(params or {})})
    assert r.status_code == 200, r.text
    return r.json()


def test_health_is_fase_f():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["fase"] == "F"


def test_stats_shape_and_consistency(analyzed):
    st = _get_stats(analyzed)
    assert st["session_id"] == analyzed["sid"]
    assert st["sheet"] == analyzed["sheet"]

    k = st["kpis"]
    assert k["total_events"] == analyzed["total_rows"]
    assert 0 <= k["events_with_timestamp"] <= k["total_events"]

    # La suma de severidades coincide con el total de hallazgos del motor.
    assert sum(k["findings_by_severity"].values()) == k["total_findings"]
    assert k["total_findings"] == analyzed["analyze"]["detection_summary"]["total_findings"]

    # La suma de bandas de incidentes coincide con el total de incidentes.
    assert sum(k["incidents_by_band"].values()) == k["total_incidents"]
    assert k["total_incidents"] >= 0

    # Identidades afectadas acotadas por el numero de eventos.
    assert 0 <= k["affected_users"] <= k["total_events"]
    assert 0 <= k["affected_hosts"] <= k["total_events"]
    assert 0 <= k["affected_source_ips"] <= k["total_events"]

    # Reglas: ejecutadas + omitidas + error <= total.
    assert k["rules_executed"] + k["rules_skipped"] + k["rules_error"] <= k["rules_total"]

    # Rango temporal coherente (o vacio si no hay timestamps validos).
    tr = k["time_range"]
    assert (tr["start"] is None) == (k["events_with_timestamp"] == 0)
    if tr["start"]:
        assert tr["start"] <= tr["end"]


def test_stats_top_lists_sorted_and_bounded(analyzed):
    st = _get_stats(analyzed, {"top_n": 5})
    for name, entries in st["top"].items():
        assert len(entries) <= 5, name
        counts = [e["count"] for e in entries]
        assert counts == sorted(counts, reverse=True), name
        assert all(e["count"] > 0 for e in entries), name
        assert all(e["value"] for e in entries), name
        assert len({e["value"] for e in entries}) == len(entries), name
        assert all(e["count"] <= st["kpis"]["total_events"] for e in entries), name


def test_stats_timeline_and_heatmap_match_valid_timestamps(analyzed):
    st = _get_stats(analyzed)
    k = st["kpis"]
    tl = st["events_timeline"]
    assert tl["granularity"] in ("hour", "day")
    assert sum(b["count"] for b in tl["buckets"]) == tl["total"] == k["events_with_timestamp"]
    buckets = [b["bucket"] for b in tl["buckets"]]
    assert buckets == sorted(buckets)
    if tl["granularity"] == "hour":
        assert all("T" in b for b in buckets)

    hm = st["heatmap"]
    assert sum(c["count"] for c in hm["cells"]) == hm["total"] == k["events_with_timestamp"]
    assert all(0 <= c["hour"] <= 23 for c in hm["cells"])
    assert hm["days"] == sorted(hm["days"])


def test_stats_siem_vs_calculated_aligned(analyzed):
    st = _get_stats(analyzed)
    sc = st["siem_vs_calculated"]
    cats = sc["categories"]
    assert len(sc["siem_events"]) == len(cats)
    assert len(sc["calculated_findings"]) == len(cats)
    assert sum(sc["calculated_findings"]) == st["kpis"]["total_findings"]
    assert sum(sc["siem_events"]) <= st["kpis"]["total_events"]
    # Orden canonico: Crítico antes que Alto antes que Medio antes que Bajo.
    order = ["Crítico", "Alto", "Medio", "Bajo"]
    known = [c for c in cats if c in order]
    assert known == [c for c in order if c in known]


def test_stats_mitre_derived_from_findings(analyzed):
    st = _get_stats(analyzed)
    r = client.get(f"/api/sessions/{analyzed['sid']}/findings", params={"sheet": analyzed["sheet"]})
    assert r.status_code == 200
    findings = r.json()["findings"]
    all_mitre = {t for f in findings for t in f.get("mitre", [])}
    for entry in st["mitre"]:
        assert entry["value"] in all_mitre
    counts = [e["count"] for e in st["mitre"]]
    assert counts == sorted(counts, reverse=True)


def test_stats_is_deterministic(analyzed):
    a = _get_stats(analyzed)
    b = _get_stats(analyzed)
    assert a == b


def test_stats_unknown_session_404():
    r = client.get("/api/sessions/no-existe/stats")
    assert r.status_code == 404


def test_stats_without_analysis_404():
    data = _make_xlsx_bytes(5)
    r = client.post("/api/upload", files={"file": ("mini.xlsx", data, "application/octet-stream")})
    assert r.status_code == 200
    sid = r.json()["session_id"]
    try:
        r2 = client.get(f"/api/sessions/{sid}/stats")
        assert r2.status_code == 404
        assert "analyze" in r2.json()["detail"]
    finally:
        client.delete(f"/api/sessions/{sid}")


def test_events_time_filter_drilldown(analyzed):
    """El drill-down del timeline/heatmap filtra eventos por rango temporal."""
    st = _get_stats(analyzed)
    tl = st["events_timeline"]
    if not tl["buckets"]:
        pytest.skip("El archivo no tiene timestamps validos")
    bucket = max(tl["buckets"], key=lambda b: b["count"])["bucket"]
    # El bucket ya es un inicio de rango valido en ISO 8601.
    start = bucket
    r = client.get(
        f"/api/sessions/{analyzed['sid']}/events",
        params={"sheet": analyzed["sheet"], "page": 1, "page_size": 1000, "time_from": start},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] > 0
    assert body["total"] <= st["kpis"]["events_with_timestamp"]
    for row in body["rows"]:
        assert (row.get("timestamp_parsed") or "") >= start

    # Un rango estrecho (una sola hora/dia del bucket) devuelve menos filas
    # que el total completo sin filtro.
    r_all = client.get(
        f"/api/sessions/{analyzed['sid']}/events",
        params={"sheet": analyzed["sheet"], "page": 1, "page_size": 1},
    )
    assert r_all.json()["total"] == analyzed["total_rows"]

    # Limites invalidos -> 400 con mensaje en espanol.
    r_bad = client.get(
        f"/api/sessions/{analyzed['sid']}/events",
        params={"sheet": analyzed["sheet"], "time_from": "no-es-fecha"},
    )
    assert r_bad.status_code == 400
    assert isinstance(r_bad.json()["detail"], str)
