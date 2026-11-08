# tests/test_report.py - Fase F: informe completo, edicion/regeneracion de secciones,
# PDF (portada/indice clicable/numeracion/tablas/evidencia) y exportaciones CSV/JSON.
# Sin hardcodear senales del ejemplo: todo se deriva del analisis real del Excel.
import json
import re
from pathlib import Path
from typing import Dict

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.reporting.exports import sanitize_csv_cell
from app.reporting.pdf import render_report_html
from app.reporting.report import NO_EVIDENCE_PHRASE, parse_section_text

client = TestClient(app)

SAMPLE = Path(__file__).resolve().parents[2] / "data" / "sample" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"


# ------------------------------- helpers -------------------------------

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


@pytest.fixture(scope="module")
def analyzed():
    sid, sheet = _analyze_sample()
    yield sid, sheet
    client.delete(f"/api/sessions/{sid}")


def _section(rep: dict, section_id: str) -> dict:
    return next(s for s in rep["sections"] if s["section_id"] == section_id)


# ------------------------- estructura del informe -------------------------

def test_health_fase_f():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["fase"] == "F"


def test_report_complete_structure(analyzed):
    sid, _ = analyzed
    r = client.get(f"/api/sessions/{sid}/report")
    assert r.status_code == 200
    rep = r.json()
    ids = [s["section_id"] for s in rep["sections"]]
    # Secciones del PLAN 9 (pulidas) + contenedores jerárquicos + anexos A-D.
    for fixed in (
        "resumen_ejecutivo", "metodologia", "tabla_hallazgos",
        "hallazgos", "incidentes", "criticidad", "impacto", "plan_accion",
        "iocs", "recomendaciones", "limitaciones", "anexo_calidad",
        "anexo_cobertura", "anexo_evidencias", "anexo_alias",
    ):
        assert fixed in ids, f"falta la seccion {fixed}"
    # La portada ya no es una sección (los datos del caso van en la cubierta del PDF).
    assert "portada" not in ids
    # Numeración jerárquica: capítulos ("5", anexos "A") y subpuntos ("5.1").
    by_id = {s["section_id"]: s for s in rep["sections"]}
    for s in rep["sections"]:
        if s["level"] == 1:
            assert s["parent"] is None
        else:
            assert s["parent"] in by_id
            assert s["number"].startswith(by_id[s["parent"]]["number"] + ".")
    assert [s["number"] for s in rep["sections"] if s["section_id"].startswith("anexo")] == ["A", "B", "C", "D"]
    # Los contenedores no son editables y los hallazgos son sus subpuntos.
    assert by_id["hallazgos"]["kind"] == "contenedor" and by_id["hallazgos"]["editable"] is False
    assert by_id["incidentes"]["kind"] == "contenedor" and by_id["incidentes"]["editable"] is False
    assert by_id["hallazgo:F-001"]["parent"] == "hallazgos"
    # Toda sección tiene título y al menos un párrafo (los contenedores llevan intro).
    assert all(s["title"] and s["paragraphs"] for s in rep["sections"])


def test_report_polish_requirements(analyzed):
    """Pulido de presentación: bandas finales, jerga fuera, plan de acción y resumen."""
    sid, _ = analyzed
    rep = client.get(f"/api/sessions/{sid}/report").json()
    findings = client.get(f"/api/sessions/{sid}/findings").json()["findings"]
    incidents = client.get(f"/api/sessions/{sid}/incidents").json()["incidents"]
    all_text = " ".join(p["text"] for s in rep["sections"] for p in s["paragraphs"])
    all_text += " " + " ".join(str(c) for s in rep["sections"] for t in s["tables"] for r in t["rows"] for c in r.values())
    # Sin jerga interna ni estados en inglés. (Una frase hecha del motor habla de
    # "Cadena de ejecución" como descripción técnica: eso no es jerga de proyecto.)
    for bad in ("fase H", "PLAN 4", "executed_no_findings", "skipped_missing_fields", "insufficient_data"):
        assert bad not in all_text, f"jerga detectada: {bad}"
    # Titulos de incidente descriptivos: sin el patrón antiguo "Cadena de N hallazgo(s) iniciada por X".
    for inc in incidents:
        assert not re.match(r"^Cadena de \d+ hallazgo", str(inc["title"])), inc["title"]
    # Resumen ejecutivo: tarjetas KPI, gráfico (dona) y un párrafo por incidente.
    resumen = _section(rep, "resumen_ejecutivo")
    assert len(resumen["cards"]) == 4
    donut = resumen["charts"][0]
    assert "<svg" in donut
    # Leyenda de la dona correcta: la cifra de cada banda aparece al lado del nombre.
    band_counts: Dict[str, int] = {}
    for f in findings:
        b = f.get("band") or f["severity"]
        band_counts[b] = band_counts.get(b, 0) + 1
    for banda, n in band_counts.items():
        assert f">{banda}</text>" in donut and f">{n}</text>" in donut, f"leyenda {banda}={n} no visible en la dona"
    blurbs = [p for p in resumen["paragraphs"] if p["text"].startswith(tuple(i["incident_id"] for i in incidents))]
    assert len(blurbs) == len(incidents)
    assert any(p["citations"] for p in blurbs)
    # 3 frases por incidente en el resumen (A2) con citas de su propio incidente.
    f_by_id = {f["finding_id"]: f for f in findings}
    for inc, blurb in zip(incidents, blurbs):
        frases = [f for f in blurb["text"].split(". ") if f]
        assert len(frases) >= 3, blurb["text"]
        propias = {str(l) for fid in inc.get("findings") or [] for l in (f_by_id.get(fid) or {}).get("evidence_log_ids") or []}
        assert set(str(c) for c in (blurb["citations"] or [])) <= propias, f"citas fuera de {inc['incident_id']}"
    # Hallazgos: capítulo con gráfico MITRE y subpuntos con meta (banda final).
    cont = _section(rep, "hallazgos")
    assert cont["charts"] and "MITRE" in cont["charts"][0]
    fh = _section(rep, "hallazgo:F-001")
    assert fh["meta"]["banda"] == (findings[0].get("band") or findings[0]["severity"])
    assert fh["meta"]["log_ids"]
    # Incidentes: cronología SVG por incidente.
    inc1 = _section(rep, "incidente:I-001")
    assert inc1["charts"] and "<svg" in inc1["charts"][0]
    # Impacto: citas deduplicadas y volumen legible (no un entero crudo gigante).
    imp = _section(rep, "impacto")
    for p in imp["paragraphs"]:
        cs = [str(c) for c in (p.get("citations") or [])]
        assert len(cs) == len(set(cs)), f"citas duplicadas en impacto: {cs}"
        if "bytes_out" in p["text"]:
            assert "bytes (" in p["text"] or "bytes." in p["text"]
    # Cobertura en español (Anexo B).
    cov_rows = _section(rep, "anexo_cobertura")["tables"][0]["rows"]
    statuses = {r["status"] for r in cov_rows}
    assert statuses <= {"Ejecutada", "Ejecutada sin hallazgos", "Datos insuficientes",
                        "Omitida por campos faltantes", "Omitida (deshabilitada)", "Error"}
    # Plan de acción: una tabla por incidente con Investigar/Contener/Remediar.
    plan_tables = _section(rep, "plan_accion")["tables"]
    assert len(plan_tables) == len(incidents)
    for t in plan_tables:
        fases = [r["fase"] for r in t["rows"]]
        assert fases == ["Investigar", "Contener", "Remediar"]
        assert all(r["prioridad"] and r["owner"] and r["sla"] for r in t["rows"])
    # Portada editable: meta por defecto y guardado.
    assert rep["meta"]["cliente"]
    r = client.put(f"/api/sessions/{sid}/report/meta", json={"cliente": "Cliente Prueba", "analista": "Analista Prueba"})
    assert r.status_code == 200
    rep2 = client.get(f"/api/sessions/{sid}/report").json()
    assert rep2["meta"]["cliente"] == "Cliente Prueba"
    assert rep2["meta"]["analista"] == "Analista Prueba"
    assert rep2["file_name"]


def test_report_one_section_per_finding_and_incident(analyzed):
    sid, _ = analyzed
    rep = client.get(f"/api/sessions/{sid}/report").json()
    findings = client.get(f"/api/sessions/{sid}/findings").json()["findings"]
    incidents = client.get(f"/api/sessions/{sid}/incidents").json()["incidents"]
    ids = [s["section_id"] for s in rep["sections"]]
    assert all(f"hallazgo:{f['finding_id']}" in ids for f in findings)
    assert all(f"incidente:{i['incident_id']}" in ids for i in incidents)
    assert rep["total_sections"] == len(rep["sections"])


def test_report_findings_summary_table_matches_motor(analyzed):
    sid, _ = analyzed
    rep = client.get(f"/api/sessions/{sid}/report").json()
    findings = client.get(f"/api/sessions/{sid}/findings").json()["findings"]
    table = _section(rep, "tabla_hallazgos")["tables"][0]
    assert len(table["rows"]) == len(findings)
    reported_ids = {row["finding_id"] for row in table["rows"]}
    assert reported_ids == {f["finding_id"] for f in findings}
    # Banda final y eventos reales; columnas compactas (sin redundancia).
    by_id = {f["finding_id"]: f for f in findings}
    assert [c["key"] for c in table["columns"]] == ["finding_id", "rule_id", "band", "score", "events", "mitre"]
    for row in table["rows"]:
        f = by_id[row["finding_id"]]
        assert row["events"] == f["total_events_matched"]
        assert row["band"] == (f.get("band") or f["severity"])


def test_report_evidence_annex_dedup(analyzed):
    sid, _ = analyzed
    rep = client.get(f"/api/sessions/{sid}/report").json()
    findings = client.get(f"/api/sessions/{sid}/findings").json()["findings"]
    sec = _section(rep, "anexo_evidencias")
    table = sec["tables"][0]
    # Deduplicada: una fila por Log_ID, con todas las citadas.
    cited = {str(row["log_id"]) for row in table["rows"]}
    expected = {lid for f in findings for lid in f["evidence_log_ids"]}
    assert cited == expected
    assert len(table["rows"]) == len(cited)
    # Texto literal del log y annex en horizontal.
    assert all("=" in row["literal"] for row in table["rows"][:10])
    assert sec["landscape"] is True


def test_report_iocs_section_only_from_incident_evidence(analyzed):
    sid, _ = analyzed
    rep = client.get(f"/api/sessions/{sid}/report").json()
    incidents = client.get(f"/api/sessions/{sid}/incidents").json()["incidents"]
    sec = _section(rep, "iocs")
    if not any(i.get("iocs") for i in incidents):
        # Sin IoCs: la seccion usa la frase obligatoria y no hay tablas.
        assert NO_EVIDENCE_PHRASE in sec["paragraphs"][0]["text"]
        assert sec["tables"] == []
        return
    rows = sec["tables"][0]["rows"]
    assert rows, "con IoCs en los incidentes la tabla debe tener filas"
    # Tipos correctos: etiquetas en español y valores que existen en los IoCs.
    valid_types = {"IPs públicas", "Hosts", "URLs", "Cuentas", "Shares SMB", "Rutas/archivos", "Servicios/Tareas", "Hashes"}
    all_values = {str(v) for inc in incidents for vals in inc["iocs"].values() for v in (vals or [])}
    for row in rows:
        assert row["tipo"] in valid_types
        assert row["valor"] in all_values
        assert row["valor"] not in ("", "-")


def test_report_impacto_and_criticidad_have_no_evidence_phrase_guard(analyzed):
    sid, _ = analyzed
    rep = client.get(f"/api/sessions/{sid}/report").json()
    findings = client.get(f"/api/sessions/{sid}/findings").json()["findings"]
    # Con hallazgos, impacto y criticidad no usan la frase (tienen datos reales).
    if findings:
        assert NO_EVIDENCE_PHRASE not in " ".join(p["text"] for p in _section(rep, "impacto")["paragraphs"])
        assert _section(rep, "criticidad")["tables"], "la criticidad debe traer tablas"


# -------------------- caso sin hallazgos: frase obligatoria --------------------

def test_report_no_findings_uses_exact_phrase():
    from app.services.sessions import AnalysisResult

    result = AnalysisResult(
        sheet="hoja_test", header_row_idx=0, columns=["a"], field_map={}, log_id_column=None,
        events=[], quality={}, detection={"findings": [], "summary": {"total_rules": 1}},
        correlation={"incidents": [], "summary": {}},
    )
    from app.reporting.report import build_report

    rep = build_report(result)
    texts = " ".join(p["text"] for s in rep["sections"] for p in s["paragraphs"])
    assert NO_EVIDENCE_PHRASE in texts
    resumen = _section(rep, "resumen_ejecutivo")
    assert resumen["paragraphs"][0]["text"] == NO_EVIDENCE_PHRASE


# ------------------------- edicion y regeneracion -------------------------

def test_parse_section_text_labels():
    paras = parse_section_text("Hecho: primera linea\nInferencia: segunda\nHipótesis: tercera\ncuarta sin etiqueta\n\n")
    assert [p["label"] for p in paras] == ["Hecho", "Inferencia", "Hipótesis", "Hecho"]
    assert paras[3]["source"] == "manual"
    assert all(p["source"] == "manual" for p in paras)


def test_edit_and_regenerate_section(analyzed):
    sid, _ = analyzed
    original = client.get(f"/api/sessions/{sid}/report").json()
    before = _section(original, "recomendaciones")
    assert before["edited"] is False

    r = client.put(
        f"/api/sessions/{sid}/report/sections/recomendaciones",
        json={"text": "Hecho: seccion editada por el analista.\nInferencia: linea adicional."},
    )
    assert r.status_code == 200, r.text
    edited = r.json()["section"]
    assert edited["edited"] is True
    assert edited["edited_at"]
    assert [p["label"] for p in edited["paragraphs"]] == ["Hecho", "Inferencia"]
    assert all(p["source"] == "manual" for p in edited["paragraphs"])

    # El GET refleja la edicion.
    rep = client.get(f"/api/sessions/{sid}/report").json()
    assert _section(rep, "recomendaciones")["edited"] is True
    assert _section(rep, "recomendaciones")["paragraphs"][0]["text"] == "seccion editada por el analista."

    # Regenerar restaura el contenido base exacto.
    r2 = client.post(f"/api/sessions/{sid}/report/sections/recomendaciones/regenerate")
    assert r2.status_code == 200
    regen = r2.json()["section"]
    assert regen["edited"] is False
    assert regen["paragraphs"] == before["paragraphs"]


def test_edit_section_validations(analyzed):
    sid, _ = analyzed
    # Vacia -> 400.
    r = client.put(f"/api/sessions/{sid}/report/sections/impacto", json={"text": "   \n  "})
    assert r.status_code == 400
    # Demasiado larga -> 400.
    r2 = client.put(f"/api/sessions/{sid}/report/sections/impacto", json={"text": "x" * 20001})
    assert r2.status_code == 400
    # Seccion inexistente -> 404.
    r3 = client.put(f"/api/sessions/{sid}/report/sections/no_existe", json={"text": "algo"})
    assert r3.status_code == 404
    # Contenedor generico ("hallazgos"/"incidentes") -> 400, no editable.
    r4 = client.put(f"/api/sessions/{sid}/report/sections/hallazgos", json={"text": "intento"})
    assert r4.status_code == 400
    r5 = client.post(f"/api/sessions/{sid}/report/sections/hallazgos/regenerate")
    assert r5.status_code == 400
    # Regenerar seccion inexistente -> 404.
    r6 = client.post(f"/api/sessions/{sid}/report/sections/no_existe/regenerate")
    assert r6.status_code == 404


# ------------------------------- PDF -------------------------------

def test_incident_timeline_stacks_coincident_marks():
    """Marcas cronológicas en el mismo instante: apiladas, no superpuestas."""
    from app.reporting.charts import incident_timeline_svg

    svg = incident_timeline_svg({"incident_id": "I-1", "timeline": [
        {"time": "2026-10-23T10:40:00", "finding_id": "F-1", "rule_id": "EXEC-006", "severity": "Medio", "score": 50},
        {"time": "2026-10-23T10:40:00", "finding_id": "F-2", "rule_id": "PERS-002", "severity": "Alto", "score": 65},
        {"time": "2026-10-23T10:49:00", "finding_id": "F-3", "rule_id": "EXF-002", "severity": "Alto", "score": 70},
    ]})
    assert svg.count("<circle") == 3, "las tres marcas deben existir"
    assert 'cy="58"' in svg and 'cy="48"' in svg, "las marcas coincidentes se apilan, no coinciden"
    assert "×2" in svg, "badge de conteo visible para el grupo"


def test_pdf_html_contains_required_parts(analyzed):
    sid, sheet = analyzed
    from app.services import sessions as store

    result = store.get_session(sid).analyses[sheet]
    from app.reporting.report import build_report

    html = render_report_html(build_report(result))
    # Portada con clasificacion, indice y tablas; la numeracion va en el pie (Playwright).
    assert "Informe técnico de análisis SOC Nivel 2" in html
    assert "Índice" in html
    assert "Confidencial – Uso interno" in html
    from app.reporting import pdf as pdf_mod

    assert "pageNumber" in Path(pdf_mod.__file__).read_text(encoding="utf-8")
    assert "totalPages" in Path(pdf_mod.__file__).read_text(encoding="utf-8")
    # Tablas y evidencia con Log_ID literal.
    assert 'class="data"' in html
    assert "Log_ID" in html
    assert "EVT-" in html
    # Sin marcadores de relleno (A11): nada de "Espacio para logo".
    assert "espacio para logo" not in html.casefold()
    # Sin HTML crudo mostrado como texto (A11): _render_para devuelve Markup.
    assert "&lt;p class=" not in html
    assert "&lt;span class=" not in html
    assert '<p class="para">' in html
    # Autoescape general: nunca hay etiqueta script cruda ni en texto.
    assert "<script" not in html.casefold()
    # El chip "Hecho" no se renderiza (marca por defecto; ensuciaba cada párrafo).
    assert ">Hecho</span>" not in html
    # Los chips con lectura distinta se conservan si el párrafo los trae.
    assert ">Inferencia</span>" in html or ">Hipótesis</span>" in html


def test_pdf_findings_flow_without_one_page_each(analyzed):
    """Saltos solo tras portada/índice, antes de hallazgos y antes de anexos."""
    sid, sheet = analyzed
    from app.services import sessions as store

    result = store.get_session(sid).analyses[sheet]
    from app.reporting.report import build_report

    rep = build_report(result)
    html = render_report_html(rep)
    breaks = html.count('class="page-break"')
    forced = sum(1 for s in rep["sections"] if s.get("break_before"))
    # 1 salto tras la portada (antes del índice) + los marcados por sección.
    assert breaks == forced + 1
    break_sections = {s["section_id"] for s in rep["sections"] if s.get("break_before")}
    assert break_sections == {"resumen_ejecutivo", "metodologia", "hallazgos", "anexo_calidad"}
    # Hallazgos a 2 columnas dentro del capítulo (hallazgos=4, incidentes=5).
    assert "findings-cols" in html
    nums = [s["number"] for s in rep["sections"]]
    assert "4.1" in nums and "5.1" in nums


def test_pdf_index_is_clickable(analyzed):
    """El índice lleva anchors internos y cada sección su id correspondiente."""
    sid, sheet = analyzed
    from app.services import sessions as store

    result = store.get_session(sid).analyses[sheet]
    from app.reporting.report import build_report

    html = render_report_html(build_report(result))
    hrefs = set(re.findall(r'href="#sec-([^"]+)"', html))
    anchors = set(re.findall(r'id="sec-([^"]+)"', html))
    assert hrefs and hrefs <= anchors  # todo enlace apunta a un id existente
    assert "hallazgos" in anchors and "incidentes" in anchors
    # 2 niveles: capítulos + subpuntos de incidentes; los hallazgos NO se listan.
    assert "incidente-I-001" in hrefs
    assert "hallazgo-F-001" not in hrefs


def test_pdf_render_real(analyzed):
    """Render real con Chromium (en cache); verifica firma %PDF y tamano."""
    sid, _ = analyzed
    r = client.get(f"/api/sessions/{sid}/report/pdf")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:5] == b"%PDF-"
    assert len(r.content) > 10000  # un informe con tablas no puede pesar nada
    # Indice clicable: Chromium debe emitir anotaciones de enlace interno (/Link).
    assert b"/Subtype" in r.content and (b"/Link" in r.content or b"/Dest" in r.content)
    # El background task limpia el temporal: no quedan PDFs temporales en data/exports.
    from app.core import config

    leftovers = list(config.EXPORT_DIR.glob("tmp_informe_*.pdf"))
    assert leftovers == []


def test_pdf_endpoint_errors():
    # Sesion inexistente.
    r = client.get("/api/sessions/inexistente/report/pdf")
    assert r.status_code == 404
    # Sesion sin analisis.
    data = SAMPLE.read_bytes()
    ru = client.post("/api/upload", files={"file": ("logs.xlsx", data, "application/octet-stream")})
    sid = ru.json()["session_id"]
    try:
        r2 = client.get(f"/api/sessions/{sid}/report/pdf")
        assert r2.status_code == 404
        r3 = client.get(f"/api/sessions/{sid}/report")
        assert r3.status_code == 404
    finally:
        client.delete(f"/api/sessions/{sid}")


# ---------------------------- exportaciones ----------------------------

def test_sanitize_csv_cell_formula_injection():
    assert sanitize_csv_cell("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert sanitize_csv_cell("+1") == "'+1"
    assert sanitize_csv_cell("-2") == "'-2"
    assert sanitize_csv_cell("@x") == "'@x"
    assert sanitize_csv_cell("normal") == "normal"
    assert sanitize_csv_cell(None) == ""


def test_iocs_csv_export(analyzed):
    sid, _ = analyzed
    r = client.get(f"/api/sessions/{sid}/exports/iocs.csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    lines = r.text.lstrip("\ufeff").splitlines()  # BOM utf-8-sig intencional para Excel
    assert lines[0] == "tipo,valor,incidentes"
    incidents = client.get(f"/api/sessions/{sid}/incidents").json()["incidents"]
    # Cada fila (tipo, valor) debe existir en los IoCs de algun incidente.
    body = lines[1:]
    if body:
        all_values = {str(v) for inc in incidents for vals in inc["iocs"].values() for v in (vals or [])}
        for line in body:
            cells = line.split(",")
            assert len(cells) == 3
            tipo, valor = cells[0], cells[1]
            assert valor.lstrip("'") in all_values, f"fila CSV {line} no procede de los IoCs del analisis"
    # Ninguna celda comienza por prefijos peligrosos (proteccion anti-formulas).
    for line in body:
        for cell in line.split(","):
            assert not cell.startswith(("=", "+", "@"))


def test_findings_json_export(analyzed):
    sid, _ = analyzed
    r = client.get(f"/api/sessions/{sid}/exports/findings.json")
    assert r.status_code == 200
    payload = json.loads(r.content.decode("utf-8"))
    findings_api = client.get(f"/api/sessions/{sid}/findings").json()["findings"]
    assert payload["total_findings"] == len(findings_api) == len(payload["findings"])
    by_id = {f["finding_id"]: f for f in findings_api}
    for f in payload["findings"]:
        src = by_id[f["finding_id"]]
        assert f["evidence_log_ids"] == src["evidence_log_ids"]
        assert f["severity"] == src["severity"]
        # Estructura determinista: sin texto de redaccion en el JSON del motor.
        assert "paragraphs" not in f


def test_findings_json_reflects_override():
    """Sesion propia para no contaminar la sesion compartida del modulo."""
    sid, _ = _analyze_sample()
    try:
        findings = client.get(f"/api/sessions/{sid}/findings").json()["findings"]
        target = findings[0]["finding_id"]
        ro = client.post(
            f"/api/sessions/{sid}/overrides",
            json={"target_type": "finding", "target_id": target, "classification": "Falso positivo", "reason": "prueba fase F"},
        )
        assert ro.status_code == 200, ro.text
        payload = json.loads(client.get(f"/api/sessions/{sid}/exports/findings.json").content.decode("utf-8"))
        f = next(x for x in payload["findings"] if x["finding_id"] == target)
        assert f["override"]["classification"] == "Falso positivo"
        assert f["override"]["reason"] == "prueba fase F"
    finally:
        client.delete(f"/api/sessions/{sid}")
