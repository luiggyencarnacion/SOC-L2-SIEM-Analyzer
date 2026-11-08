# reporting/pdf.py - Render del informe a PDF (fase F + pulido de presentación).
# Jinja2 (autoescape activado) genera el HTML A4; Playwright con Chromium local
# lo imprime a PDF. Seguridad: toda la evidencia se inserta como texto escapado;
# los únicos fragmentos "raw" son los SVG generados por nosotros (charts.py),
# cuyo texto interno ya se escapa XML.
# Paginación del índice: Chromium no soporta target-counter, así que se hacen
# DOS pasadas — la 1ª produce el PDF, se extrae la página destino de cada enlace
# del índice (anotaciones /Dest) y la 2ª inyecta esos números en el índice.
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, select_autoescape

BAND_CLASS = {"Crítico": "critico", "Alto": "alto", "Medio": "medio", "Bajo": "bajo"}

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>{{ title }}</title>
<style>
  @page { size: A4; margin: 10mm 0 14mm 0; }
  @page apaisada { size: A4 landscape; margin: 10mm 0 14mm 0; }
  .apaisada { page: apaisada; }
  * { box-sizing: border-box; }
  body { font-family: "Segoe UI", Arial, sans-serif; font-size: 10.5pt; color: #1a2332; margin: 0; }
  .page-break { page-break-before: always; }
  /* ---------- Portada ---------- */
  /* Sin altura forzada: con margen de pagina real, vh no es fiable en print. */
  .cover { padding: 0 2cm; }
  .cover-top { display: flex; justify-content: flex-end; align-items: flex-start; margin-top: 0.4cm; }
  .class-chip { background: #b91c1c; color: #fff; font-weight: 700; font-size: 9pt;
                padding: 5px 12px; border-radius: 4px; }
  .cover-main { margin-top: 2.6cm; }
  .cover h1 { font-size: 25pt; margin: 0 0 0.25cm 0; color: #0b3a5d; line-height: 1.2; }
  .cover h2 { font-size: 12.5pt; font-weight: normal; color: #45566b; margin: 0; }
  .cover-file { margin-top: 0.7cm; font-size: 12pt; font-weight: 600; color: #1a2332; }
  .cover-meta { margin-top: 1.6cm; border-collapse: collapse; width: 100%; max-width: 15.5cm; }
  .cover-meta td { border: 1px solid #c6d2de; padding: 7px 10px; font-size: 10.5pt; }
  .cover-meta td.k { background: #eef3f8; font-weight: 600; width: 30%; }
  .cover-foot { margin-top: 3.4cm; color: #5a6b7e; font-size: 9pt; padding-bottom: 0.4cm; }
  /* ---------- Indice (2 niveles, clicable, con paginas) ---------- */
  h2.chapter { font-size: 15pt; color: #0b3a5d; border-bottom: 2px solid #0b3a5d; padding-bottom: 4px; margin: 0.5cm 0 0.25cm 0; }
  h3.sub { font-size: 12pt; color: #16425f; margin: 0.4cm 0 0.2cm 0; }
  .toc ul { list-style: none; padding-left: 0.2cm; }
  .toc li { margin: 2px 0; }
  .toc li.l1 { font-weight: 600; margin-top: 7px; }
  .toc li.l2 { margin-left: 1.0cm; font-weight: normal; font-size: 9.5pt; }
  .toc a { color: inherit; text-decoration: none; }
  .toc .row { display: flex; }
  .toc .t { flex: 1; }
  .toc .p { width: 1.4cm; text-align: right; color: #45566b; }
  /* ---------- Contenido ---------- */
  .content { padding: 0 2cm 0.2cm 2cm; }
  p.para { margin: 0.18cm 0; text-align: left; break-inside: avoid; }
  h2.chapter, h3.flow, h3.sub { break-after: avoid; }
  /* Hallazgos e incidentes: tarjetas en flujo continuo, indivisibles. */
  h3.flow { font-size: 12.5pt; color: #0b3a5d; margin: 0.45cm 0 0.2cm 0; padding-bottom: 3px;
            border-bottom: 1px solid #b7c6d6; }
  .card { border: 1px solid #c6d2de; border-radius: 8px; padding: 7px 10px; margin: 0.25cm 0;
          break-inside: avoid; background: #fbfdff; }
  .card p.para { line-height: 1.25; }
  /* Hallazgos a 2 columnas para densidad (Chromium imprime CSS columns). */
  .findings-cols { column-count: 2; column-gap: 16px; margin-top: 0.15cm; }
  .findings-cols .card { margin: 0 0 8px 0; font-size: 8.5pt; padding: 6px 8px; }
  .findings-cols .card .card-meta { font-size: 7pt; margin: 3px 0 4px 0; }
  .findings-cols .card p.para { font-size: 8.5pt; margin: 0.12cm 0; line-height: 1.22; }
  .card-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .card-num { font-weight: 700; color: #0b3a5d; }
  .card-meta { color: #45566b; font-size: 8.5pt; margin: 4px 0 6px 0; }
  .chip { display: inline-block; font-size: 8pt; font-weight: 700; padding: 2px 9px;
          border-radius: 10px; color: #fff; }
  .chip.critico { background: #b91c1c; }  /* Crítico: rojo */
  .chip.alto    { background: #ea580c; }  /* Alto: naranja */
  .chip.medio   { background: #ca8a04; }  /* Medio: amarillo (ámbar oscuro) */
  .chip.bajo    { background: #15803d; }  /* Bajo: verde */
  .chip.override { background: #0b3a5d; font-weight: 600; }
  .lbl { display: inline-block; font-size: 7.5pt; font-weight: 700; padding: 1px 6px; border-radius: 3px;
         color: #fff; background: #5a6b7e; margin-right: 6px; }
  .lbl-Hecho { background: #1d7a46; }
  .lbl-Inferencia { background: #b07513; }
  .lbl-Hipotesis { background: #7a3b8f; }
  .lbl-manual { background: #0b3a5d; }
  .citation { font-size: 8.5pt; color: #45566b; }
  /* Tarjetas KPI del resumen */
  .cards { display: flex; gap: 8px; margin: 0.2cm 0 0.3cm 0; }
  .kpi { flex: 1; border: 1px solid #c6d2de; border-radius: 8px; padding: 8px 10px; background: #f4f7fa; }
  .kpi .v { font-size: 18pt; font-weight: 700; color: #0b3a5d; }
  .kpi .l { font-size: 9pt; color: #45566b; }
  .kpi .h { font-size: 8pt; color: #8fa3b8; }
  .chart { margin: 0.18cm 0; }
  /* ---------- Tablas ---------- */
  table.data { border-collapse: collapse; width: 100%; margin: 0.15cm 0 0.3cm 0; font-size: 8.5pt;
               table-layout: fixed; }
  table.data th { background: #0b3a5d; color: #fff; text-align: left; padding: 5px 7px; border: 1px solid #0b3a5d; }
  table.data td { border: 1px solid #c6d2de; padding: 4px 7px; vertical-align: top;
                  word-break: keep-all; hyphens: none; break-inside: avoid; }
  table.data tr:nth-child(even) td { background: #f4f7fa; }
  table.data thead { display: table-header-group; }
  td.mono { font-family: Consolas, "Courier New", monospace; font-size: 7.5pt; overflow-wrap: anywhere; }
  .band { font-weight: 700; }
  .band.critico { color: #b91c1c; }
  .band.alto { color: #ea580c; }
  .band.medio { color: #a3770a; }
  .band.bajo { color: #15803d; }
  .novalue { font-style: italic; color: #6b7a8d; }
  /* Anexo de evidencias compacto (horizontal, monoespaciado). */
  #sec-anexo_evidencias table.data { font-size: 6.5pt; }
  #sec-anexo_evidencias table.data td { padding: 2px 4px; }
  #sec-anexo_evidencias td.mono { font-size: 6pt; }
</style>
</head>
<body>
  {# ---------- Portada ---------- #}
  <div class="cover">
    <div class="cover-top">
      <div class="class-chip">Confidencial – Uso interno</div>
    </div>
    <div class="cover-main">
      <h1>Informe técnico de análisis SOC Nivel 2</h1>
      <h2>Detección determinista por reglas · correlación · evidencia por Log_ID</h2>
      <div class="cover-file">{{ file_name }}</div>
    </div>
    <table class="cover-meta">
      <tr><td class="k">Cliente</td><td>{{ meta.cliente }}</td></tr>
      <tr><td class="k">Analista</td><td>{{ meta.analista }}</td></tr>
      <tr><td class="k">Fecha del informe</td><td>{{ generated_at_human }}</td></tr>
      <tr><td class="k">Archivo analizado</td><td>{{ file_name }} — hoja «{{ sheet }}»</td></tr>
      <tr><td class="k">Clasificación</td><td>Confidencial – Uso interno</td></tr>
    </table>
    <div class="cover-foot">Generado localmente · sin envío de datos a terceros salvo configuración IA explícita</div>
  </div>

  {# ---------- Índice (2 niveles, clicable, con páginas) ---------- #}
  <div class="page-break"></div>
  <div class="content toc">
    <h2 class="chapter">Índice</h2>
    <ul>
      {% for e in toc %}
      <li class="{{ 'l1' if e.level == 1 else 'l2' }}">
        <a href="#{{ e.anchor }}"><span class="row"><span class="t">{{ e.number }}. {{ e.title }}</span><span class="p">{{ e.page }}</span></span></a>
      </li>
      {% endfor %}
    </ul>
  </div>

  {# ---------- Secciones ---------- #}
  {% for s in sections %}
  {% if s.break_before %}<div class="page-break"></div>{% endif %}
  <div class="content{{ ' apaisada' if s.landscape else '' }}" id="{{ s.anchor }}">
    {% if s.level == 1 %}
      <h2 class="chapter">{{ s.number }}. {{ s.title }}</h2>
    {% else %}
      <h3 class="flow">{{ s.number }}. {{ s.title }}</h3>
    {% endif %}

    {% if s.kind == 'hallazgo' and s.meta %}
      <div class="card">
        <div class="card-head">
          <span class="card-num">{{ s.meta.id }}</span>
          <span class="chip {{ s.meta.banda_cls }}">{{ s.meta.banda }}</span>
          <span class="card-num">score {{ s.meta.score }}</span>
          {% if s.meta.override %}<span class="chip override">override: {{ s.meta.override }}</span>{% endif %}
        </div>
        <div class="card-meta">
          Regla {{ s.meta.regla }} · MITRE {{ s.meta.mitre | join(', ') if s.meta.mitre else '—' }}
          {% if s.meta.usuarios %} · Cuentas: {{ s.meta.usuarios | join(', ') }}{% endif %}
          {% if s.meta.hosts %} · Hosts: {{ s.meta.hosts | join(', ') }}{% endif %}
          {% if s.meta.ips %} · IPs: {{ s.meta.ips | join(', ') }}{% endif %}
          <br>Evidencia ({{ s.meta.total_evidencia }}): {{ s.meta.log_ids | join(', ') }}
        </div>
        {% for p in s.paragraphs %}{{ para(p) }}{% endfor %}
      </div>
    {% elif s.kind == 'incidente' and s.meta %}
      <div class="card">
        <div class="card-head">
          <span class="card-num">{{ s.meta.id }}</span>
          <span class="chip {{ s.meta.banda_cls }}">{{ s.meta.banda }}</span>
          <span class="card-num">score {{ s.meta.score }}</span>
          {% if s.meta.override %}<span class="chip override">override: {{ s.meta.override }}</span>{% endif %}
        </div>
        <div class="card-meta">
          Hallazgos: {{ s.meta.hallazgos }} · Fases: {{ s.meta.fases | join(' → ') if s.meta.fases else '—' }}
          {% if s.meta.hosts %} · Hosts: {{ s.meta.hosts | join(', ') }}{% endif %}
          {% if s.meta.usuarios %} · Cuentas: {{ s.meta.usuarios | join(', ') }}{% endif %}
        </div>
        {% for c in s.charts %}<div class="chart">{{ c | safe }}</div>{% endfor %}
        {% for p in s.paragraphs %}{{ para(p) }}{% endfor %}
      </div>
    {% else %}
      {% if s.cards %}
      <div class="cards">
        {% for c in s.cards %}
        <div class="kpi"><div class="v">{{ c.value }}</div><div class="l">{{ c.label }}</div><div class="h">{{ c.hint }}</div></div>
        {% endfor %}
      </div>
      {% endif %}
      {% for c in s.charts %}<div class="chart">{{ c | safe }}</div>{% endfor %}
      {% for p in s.paragraphs %}{{ para(p) }}{% endfor %}
    {% endif %}

    {% for t in s.tables %}
    <h3 class="sub">{{ t.title }}</h3>
    <table class="data">
      {% if t.widths %}<colgroup>{% for w in t.widths %}<col style="width:{{ w }}%">{% endfor %}</colgroup>{% endif %}
      <thead><tr>{% for col in t.columns %}<th>{{ col.label }}</th>{% endfor %}</tr></thead>
      <tbody>
        {% for row in t.rows %}
        <tr>
          {% for col in t.columns %}
          <td {% if col.key in t.mono_cols %}class="mono"{% endif %}>
            {%- set v = row[col.key] -%}
            {%- if col.key in ('band',) -%}<span class="band {{ v | banda_cls }}">{{ v }}</span>
            {%- elif v is none or v == '' -%}<span class="novalue">—</span>
            {%- else -%}{{ v }}
            {%- endif -%}
          </td>
          {% endfor %}
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% endfor %}

    {% if s.section_id == 'hallazgos' and children_hallazgos %}
    {# Tarjetas de hallazgo a 2 columnas, indivisibles, en flujo continuo #}
    <div class="findings-cols">
      {% for c in children_hallazgos %}
      <div class="card" id="{{ c.anchor }}">
        <div class="card-head">
          <span class="card-num">{{ c.meta.id }}</span>
          <span class="chip {{ c.meta.banda_cls }}">{{ c.meta.banda }}</span>
          <span class="card-num" style="font-weight:600;font-size:8.5pt;">score {{ c.meta.score }}</span>
          {% if c.meta.override %}<span class="chip override">override: {{ c.meta.override }}</span>{% endif %}
        </div>
        <div class="card-meta">
          {{ c.meta.regla }} · MITRE {{ c.meta.mitre | join(', ') if c.meta.mitre else '—' }}
          {% if c.meta.usuarios %} · {{ c.meta.usuarios | join(', ') }}{% endif %}
          {% if c.meta.hosts %} · {{ c.meta.hosts | join(', ') }}{% endif %}
          {% if c.meta.ips %} · {{ c.meta.ips | join(', ') }}{% endif %}
          <br>Evidencia ({{ c.meta.total_evidencia }}): {{ c.meta.log_ids | join(', ') }}
        </div>
        {% for p in c.paragraphs %}{{ para(p) }}{% endfor %}
      </div>
      {% endfor %}
    </div>
    {% endif %}
  </div>
  {% endfor %}
</body>
</html>
"""

_env = Environment(autoescape=select_autoescape(["html"]))


def _band_cls(value: Any) -> str:
    return BAND_CLASS.get(str(value or ""), "medio")


_env.filters["banda_cls"] = _band_cls


def _render_para(p: Dict[str, Any]) -> str:
    """Párrafo con etiqueta y citas, generado con escape explícito.

    Devuelve Markup: Jinja2 con autoescape escapa cualquier string ajeno
    al entorno (mostraba el HTML crudo en el PDF si se devuelve str plano).
    """
    label = str(p.get("label") or "")
    label_cls = {"Hecho": "lbl-Hecho", "Inferencia": "lbl-Inferencia", "Hipótesis": "lbl-Hipotesis"}.get(
        label, "lbl-Hecho"
    )
    from markupsafe import Markup, escape

    # El chip "Hecho" no se renderiza: es la marca por defecto de toda la
    # plantilla y ensuciaba el arranque de cada párrafo. Se conservan los
    # chips de Inferencia/Hipótesis porque sí cambian la lectura.
    show_label = label in ("Inferencia", "Hipótesis")
    parts = ['<p class="para">']
    if show_label:
        parts.append(f'<span class="lbl {label_cls}">{escape(label)}</span>')
    if p.get("source") == "manual":
        parts.append('<span class="lbl lbl-manual">manual</span>')
    parts.append(escape(p.get("text") or ""))
    cites = [str(c) for c in (p.get("citations") or [])]
    if cites:
        joined = escape(", ".join(cites))
        parts.append(f' <span class="citation">[Evidencia: {joined}]</span>')
    parts.append("</p>")
    return Markup("".join(parts))


_env.globals["para"] = _render_para
_template = _env.from_string(_HTML_TEMPLATE)


def _toc_entries(sections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Entradas del índice: capítulos (nivel 1) + subpuntos de incidentes.
    Los hallazgos no se listan individualmente ( requisito del diseño )."""
    out = []
    for s in sections:
        if s.get("level") == 1 or s.get("parent") == "incidentes":
            out.append({
                "number": s.get("number"),
                "title": s.get("title"),
                "level": s.get("level", 1),
                "anchor": _anchor_of(s),
                "page": "",
            })
    return out


def _anchor_of(s: Dict[str, Any]) -> str:
    return "sec-" + str(s.get("section_id") or "").replace(":", "-")


def render_report_html(report: Dict[str, Any], toc_pages: Optional[List[int]] = None) -> str:
    """HTML del informe: portada, índice clicable y secciones (con o sin páginas)."""
    sections: List[Dict[str, Any]] = report.get("sections") or []
    toc = _toc_entries(sections)
    if toc_pages:
        for i, e in enumerate(toc):
            if i < len(toc_pages) and toc_pages[i]:
                e["page"] = str(toc_pages[i])
    # Meta de tarjeta para hallazgos/incidentes (clases CSS de banda) + árbol
    # para el layout a 2 columnas de los hallazgos.
    prepared: List[Dict[str, Any]] = []
    children_hallazgos: List[Dict[str, Any]] = []
    for s in sections:
        g = dict(s)
        g["anchor"] = _anchor_of(s)
        meta = dict(s.get("meta") or {})
        if meta:
            meta["banda_cls"] = _band_cls(meta.get("banda"))
            meta["id"] = (s.get("section_id") or "").split(":")[-1]
            g["meta"] = meta
        if s.get("parent") == "hallazgos":
            children_hallazgos.append(g)  # se renderizan dentro del capítulo
        else:
            prepared.append(g)
    return _template.render(
        title="Informe de análisis SOC L2",
        sections=prepared,
        children_hallazgos=children_hallazgos,
        toc=toc,
        file_name=report.get("file_name") or "(archivo en sesión)",
        sheet=report.get("sheet") or "",
        meta=report.get("meta") or {},
        generated_at_human=report.get("generated_at_human") or report.get("generated_at") or "",
    )


def _extract_toc_pages(pdf_bytes: bytes, expected: int) -> Optional[List[int]]:
    """Extrae, en orden, la página destino de cada enlace del índice (1ª pasada).

    Chromium emite destinos CON NOMBRE: cada anotación /Link lleva /Dest /sec-...,
    y el árbol /Dests del catálogo mapea cada nombre a [objeto_de_página /XYZ ...].
    El ordinal de página se obtiene recorriendo el árbol /Pages en profundidad.
    Devuelve None si no puede parsearse (el índice queda sin números).
    """
    try:
        # 1. Tipos de objeto: numero -> Page | Pages.
        objtype: Dict[int, str] = {}
        for m in re.finditer(rb"(\d+)\s+0\s+obj\s*<</Type\s*/(Page[s]?)\b", pdf_bytes):
            objtype[int(m.group(1))] = m.group(2).decode()
        if not objtype:
            return None
        # 2. Arbol /Pages: kids por numero de nodo.
        kids_map: Dict[int, List[int]] = {}
        for m in re.finditer(rb"(\d+)\s+0\s+obj\s*<</Type\s*/Pages\b[^>]*?/Kids\s*\[([^\]]+)\]", pdf_bytes):
            node = int(m.group(1))
            kids_map[node] = [int(x) for x in re.findall(rb"(\d+)\s+0\s+R", m.group(2))]
        root_ref = re.search(rb"/Pages\s+(\d+)\s+0\s+R", pdf_bytes)
        if not root_ref or int(root_ref.group(1)) not in kids_map:
            return None
        page_order: List[int] = []

        def _walk(node: int) -> None:
            for kid in kids_map.get(node, []):
                t = objtype.get(kid)
                if t == "Page":
                    page_order.append(kid)
                elif t == "Pages":
                    _walk(kid)

        _walk(int(root_ref.group(1)))
        page_no = {obj: i + 1 for i, obj in enumerate(page_order)}
        if not page_no:
            return None
        # 3. Mapa nombre -> pagina (arbol /Dests).
        dest_map: Dict[str, int] = {}
        for m in re.finditer(rb"/(sec-[A-Za-z0-9_-]+)\s*\[\s*(\d+)\s+0\s+R", pdf_bytes):
            ref = int(m.group(2))
            if ref in page_no:
                dest_map[m.group(1).decode()] = page_no[ref]
        # 4. Nombres en el orden de las anotaciones /Link del documento.
        # Cada entrada del índice puede partirse en varias anotaciones (una por
        # línea renderizada): se colapsan duplicados consecutivos.
        names = re.findall(rb"/Dest\s*/(sec-[A-Za-z0-9_-]+)", pdf_bytes)
        unique_in_order: List[bytes] = []
        for n in names:
            if not unique_in_order or unique_in_order[-1] != n:
                unique_in_order.append(n)
        pages = [dest_map.get(n.decode()) for n in unique_in_order]
        pages = [p for p in pages if p]
        if len(pages) >= expected:
            return pages[:expected]
        return None
    except Exception:
        return None


def render_report_pdf(report: Dict[str, Any], out_path: Path) -> Path:
    """Renderiza el informe a PDF A4 (mixto vertical/horizontal) con:
    portada, índice clicable a 2 niveles con números de página (2 pasadas),
    numeración de páginas en el pie y tablas con cabecera repetida."""
    from playwright.sync_api import sync_playwright

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n_entries = len(_toc_entries(report.get("sections") or []))
    footer = (
        '<div style="width:100%;font-size:8pt;color:#45566b;padding:0 2cm;'
        'display:flex;justify-content:space-between;">'
        "<span>SOC L2 SIEM Analyzer — informe de análisis</span>"
        '<span>Página <span class="pageNumber"></span> de <span class="totalPages"></span></span>'
        "</div>"
    )

    def _print(html: str, path: Path) -> None:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            try:
                page = browser.new_page()
                page.set_content(html, wait_until="load")
                page.emulate_media(media="print")
                page.pdf(
                    path=str(path),
                    prefer_css_page_size=True,
                    print_background=True,
                    display_header_footer=True,
                    header_template="<span></span>",
                    footer_template=footer,
                    margin={"top": "10mm", "bottom": "14mm", "left": "0cm", "right": "0cm"},
                )
            finally:
                browser.close()

    # Pasada 1: sin números de página en el índice.
    html = render_report_html(report)
    tmp1 = out_path.with_suffix(".pass1.pdf")
    _print(html, tmp1)
    pages = _extract_toc_pages(tmp1.read_bytes(), n_entries)
    try:
        tmp1.unlink()
    except OSError:
        pass
    # Pasada 2 (solo si el parseo funcionó): índice con números de página.
    if pages:
        html = render_report_html(report, toc_pages=pages)
    _print(html, out_path)
    return out_path
