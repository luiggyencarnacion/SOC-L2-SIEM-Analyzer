# tests/test_api.py - Integracion de la API fase A: upload invalido/valido, analyze,
# tabla con paginacion/busqueda/filtros/orden, calidad y aliases. Sin hardcodear
# valores del ejemplo: se deriva todo del archivo cargado en el test.
import io
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

SAMPLE = Path(__file__).resolve().parents[2] / "data" / "sample" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"


def _make_xlsx_bytes(num_rows: int, macro: bool = False) -> bytes:
    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "uno"
    ws.append(["Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Result"])
    for i in range(1, num_rows + 1):
        ws.append([f"L-{i:04d}", f"2026-01-01 00:{i % 60:02d}:0{i % 10}", f"HO-{i % 5}", str(1000 + i), f"usr{i % 7}", "Success"])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_upload_rejects_non_xlsx():
    r = client.post("/api/upload", files={"file": ("log.csv", b"a,b,c", "text/csv")})
    assert r.status_code == 400
    assert isinstance(r.json()["detail"], str)


def test_upload_rejects_corrupt_zip():
    r = client.post("/api/upload", files={"file": ("bad.xlsx", b"PK\x03\x04-corrupto", "application/vnd.ms-excel")})
    assert r.status_code == 400


def test_upload_valid_and_analyze_end_to_end():
    data = SAMPLE.read_bytes()
    r = client.post("/api/upload", files={"file": ("logs.xlsx", data, "application/octet-stream")})
    assert r.status_code == 200, r.text
    body = r.json()
    sid = body["session_id"]
    assert body["size_bytes"] == len(data)
    assert any(s["name"] for s in body["sheets"])
    sheet = body["sheets"][0]["name"]
    assert body["mappings"][0]["suggestions"], "debe proponer mapeo"

    total_rows = body["sheets"][0]["data_rows"]
    # mapeo sugerido: enviamos column->field tal cual la API sugirió
    mapping = [{"column": s["column"], "field": s["field"]} for s in body["mappings"][0]["suggestions"]]
    r2 = client.post(
        f"/api/sessions/{sid}/analyze",
        json={"sheet": sheet, "header_row": body["sheets"][0]["header_row"], "mapping": mapping},
    )
    assert r2.status_code == 200, r2.text
    a2 = r2.json()
    assert a2["total_rows"] == total_rows

    # Tabla: primera pagina
    r3 = client.get(f"/api/sessions/{sid}/events", params={"page": 1, "page_size": 50})
    assert r3.status_code == 200
    ev = r3.json()
    assert ev["total"] == total_rows
    assert len(ev["rows"]) == 50
    assert ev["rows"][0]["log_id"]

    # Paginacion
    r4 = client.get(f"/api/sessions/{sid}/events", params={"page": 2, "page_size": 50, "sheet": sheet})
    assert r4.status_code == 200
    rows_page2 = r4.json()["rows"]
    assert rows_page2 and rows_page2[0]["row_number"] > 50

    # Busqueda global: usa un valor visible en la primera pagina
    search_value = str(ev["rows"][0]["log_id"])
    r5 = client.get(f"/api/sessions/{sid}/events", params={"q": search_value})
    assert r5.status_code == 200
    assert r5.json()["total"] >= 1
    assert all(
        search_value.casefold() in str(r.get("log_id", "")).casefold()
        for r in r5.json()["rows"]
    )

    # Orden desc por row_number
    r6 = client.get(f"/api/sessions/{sid}/events", params={"sort": "row_number", "direction": "desc", "page_size": 10})
    rows_desc = r6.json()["rows"]
    assert rows_desc[0]["row_number"] >= rows_desc[-1]["row_number"]

    # Filtro por columna (host_raw del primer evento): todas las filas devueltas
    # deben tener ese valor; el total debe ser menor que el total global.
    host_value = str(ev["rows"][0].get("host_raw") or "")
    import json as _json

    if host_value:
        paired = []
        page = 1
        distinct_hosts: set = set()
        while True:
            rp = client.get(
                f"/api/sessions/{sid}/events",
                params={"filters": _json.dumps({"host_raw": host_value}), "page": page, "page_size": 250, "sheet": sheet},
            )
            js = rp.json()
            distinct_hosts |= {r["host_raw"] for r in js["rows"]}
            if page * 250 >= js["total"]:
                break
            page += 1
        assert distinct_hosts == {host_value}, f"el filtro debia dejar solo {host_value}"
        assert js["total"] <= ev["total"]

    # Detalle de fila por Log_ID
    lid = ev["rows"][0]["log_id"]
    r8 = client.get(f"/api/sessions/{sid}/events/{lid}")
    assert r8.status_code == 200
    assert r8.json()["raw"]["row"]

    # Calidad y aliases
    r9 = client.get(f"/api/sessions/{sid}/quality")
    assert r9.status_code == 200
    q = r9.json()
    assert q["total_rows"] == total_rows
    assert any(c["column"] == "timestamp_raw" for c in q["columns"])
    assert q["timestamp"]["total"] == total_rows

    r10 = client.get(f"/api/sessions/{sid}/aliases")
    assert r10.status_code == 200
    al = r10.json()
    assert isinstance(al["hosts"], list) and isinstance(al["users"], list)

    # Delete
    r11 = client.delete(f"/api/sessions/{sid}")
    assert r11.status_code == 200
    assert client.get(f"/api/sessions/{sid}").status_code == 404


def test_analyze_requires_structure():
    data = _make_xlsx_bytes(3)
    r = client.post("/api/upload", files={"file": ("ok.xlsx", data, "application/octet-stream")})
    sid = r.json()["session_id"]
    sheet = r.json()["sheets"][0]["name"]
    # Mapeo vacio pero la estructura minima pasa porque no mapeamos ts ni identidades
    r2 = client.post(
        f"/api/sessions/{sid}/analyze",
        json={"sheet": sheet, "header_row": 1, "mapping": [
            {"column": "Result", "field": "result"},
        ]},
    )
    assert r2.status_code == 400  # sin ts ni identidades
    client.delete(f"/api/sessions/{sid}")


def test_synthetic_log_ids_when_no_log_id_column():
    data = _make_xlsx_bytes(4)
    r = client.post("/api/upload", files={"file": ("no_id.xlsx", data, "application/octet-stream")})
    body = r.json()
    sid = body["session_id"]
    sheet = body["sheets"][0]["name"]
    mapping = [
        {"column": c["column"], "field": c["field"]}
        for c in body["mappings"][0]["suggestions"]
        if c["field"] != "log_id"
    ]
    r2 = client.post(f"/api/sessions/{sid}/analyze", json={"sheet": sheet, "header_row": 1, "mapping": mapping})
    assert r2.status_code == 200
    total = r2.json()["total_rows"]
    r3 = client.get(f"/api/sessions/{sid}/events", params={"page_size": 250})
    rows = r3.json()["rows"]
    assert all(r["log_id"].startswith("ROW-") for r in rows)
    assert any("log_id_synthetic" in r["quality_flags"] for r in rows)
    assert total == 4
    client.delete(f"/api/sessions/{sid}")
