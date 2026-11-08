# reporting/charts.py - Graficos SVG incrustados en el informe PDF (fase de pulido).
# Todo determinista a partir de los datos del analisis; sin librerias externas.
# El texto de las etiquetas se escapa XML para insertarse con |safe en Jinja.
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape as _xml_escape

# Colores de banda coherentes con los chips del PDF y la UI.
BAND_COLORS: Dict[str, str] = {
    "Crítico": "#b91c1c",   # rojo
    "Alto": "#ea580c",      # naranja
    "Medio": "#ca8a04",     # amarillo oscuro (legible)
    "Bajo": "#15803d",      # verde
}
BAND_ORDER = ["Crítico", "Alto", "Medio", "Bajo"]
_TEXT = "#1a2332"
_MUTED = "#5a6b7e"


def _esc(v: Any) -> str:
    return _xml_escape(str(v if v is not None else ""))


def _band_color(band: Any) -> str:
    return BAND_COLORS.get(str(band or ""), "#5a6b7e")


def donut_svg(counts: Dict[str, int], title: str = "Hallazgos por criticidad") -> str:
    """Dona de criticidad con leyenda numerada; color + texto siempre."""
    total = sum(counts.values())
    if total <= 0:
        return _empty_svg(title, "Sin hallazgos")
    # Orden canonico; extras al final.
    ordered = [(b, counts[b]) for b in BAND_ORDER if counts.get(b)]
    ordered += [(b, c) for b, c in counts.items() if b not in BAND_ORDER and c]
    # El aro baja (cy=100) para no pisar el titulo; viewBox 350 para que la
    # columna de cifras (text-anchor end) no se recorte en el borde.
    cx, cy, r_out, r_in = 90, 100, 78, 50
    import math

    paths = []
    start = -90.0
    for band, count in ordered:
        frac = count / total
        end = start + frac * 360.0
        large = 1 if (end - start) > 180 else 0
        a0, a1 = math.radians(start), math.radians(end)
        x0, y0 = cx + r_out * math.cos(a0), cy + r_out * math.sin(a0)
        x1, y1 = cx + r_out * math.cos(a1), cy + r_out * math.sin(a1)
        xi1, yi1 = cx + r_in * math.cos(a1), cy + r_in * math.sin(a1)
        xi0, yi0 = cx + r_in * math.cos(a0), cy + r_in * math.sin(a0)
        if frac >= 0.999:
            d = (f"M {cx - r_out} {cy} A {r_out} {r_out} 0 1 1 {cx + r_out} {cy} "
                 f"A {r_out} {r_out} 0 1 1 {cx - r_out} {cy} "
                 f"M {cx - r_in} {cy} A {r_in} {r_in} 0 1 0 {cx + r_in} {cy} "
                 f"A {r_in} {r_in} 0 1 1 {cx - r_in} {cy} Z")
            paths.append(f'<path d="{d}" fill="{_band_color(band)}" fill-rule="evenodd"/>')
        else:
            d = (f"M {x0:.2f} {y0:.2f} A {r_out} {r_out} 0 {large} 1 {x1:.2f} {y1:.2f} "
                 f"L {xi1:.2f} {yi1:.2f} A {r_in} {r_in} 0 {large} 0 {xi0:.2f} {yi0:.2f} Z")
            paths.append(f'<path d="{d}" fill="{_band_color(band)}"/>')
        start = end
    legend = "".join(
        f'<g transform="translate(200,{44 + i * 34})">'
        f'<rect width="14" height="14" rx="3" fill="{_band_color(b)}"/>'
        f'<text x="22" y="12" font-size="14" fill="{_TEXT}">{_esc(b)}</text>'
        f'<text x="120" y="12" font-size="14" font-weight="bold" fill="{_TEXT}" text-anchor="end">{c}</text>'
        f"</g>"
        for i, (b, c) in enumerate(ordered)
    )
    return (
        f'<svg viewBox="0 0 350 230" width="350" height="230" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="{_esc(title)}">'
        f'<text x="0" y="16" font-size="14" font-weight="bold" fill="{_TEXT}">{_esc(title)}</text>'
        f'{"".join(paths)}'
        f'<text x="{cx}" y="{cy - 4}" text-anchor="middle" font-size="26" font-weight="bold" fill="{_TEXT}">{total}</text>'
        f'<text x="{cx}" y="{cy + 18}" text-anchor="middle" font-size="11" fill="{_MUTED}">hallazgos</text>'
        f"{legend}</svg>"
    )


def incident_timeline_svg(inc: Dict[str, Any], width: int = 660) -> str:
    """Linea de tiempo del incidente: un punto por hallazgo de la timeline.

    Varios hallazgos pueden compartir el mismo minuto (p. ej. ejecuciones
    encadenadas): si se dibujan en la misma coordenada quedan invisibles unos
    sobre otros. Se apilan con desfase vertical determinista y un contador
    "xN" cuando coincide mas de una marca en el mismo instante.
    """
    steps = [s for s in (inc.get("timeline") or []) if s.get("time")]
    title = f"Cronologia {inc.get('incident_id', '')}".strip()
    if not steps:
        return _empty_svg(title, "Sin marcas temporales")
    from datetime import datetime

    def _ts(v: Any) -> Optional[datetime]:
        try:
            return datetime.fromisoformat(str(v))
        except (ValueError, TypeError):
            return None

    times = [(_ts(s["time"]), s) for s in steps]
    times = [(t, s) for t, s in times if t]
    if not times:
        return _empty_svg(title, "Sin marcas temporales")
    t0 = min(t for t, _ in times)
    t1 = max(t for t, _ in times)
    span = max((t1 - t0).total_seconds(), 1.0)
    pad = 60
    usable = width - 2 * pad
    # Agrupar por instante exacto para apilar marcas coincidentes.
    groups: "OrderedDict[datetime, List[Dict[str, Any]]]" = {}
    for t, s in times:
        groups.setdefault(t, []).append(s)
    # Filas apiladas: centro en la linea ±10/±20 px (cabe hasta 5 por instante
    # con r=5; mas de 5 recicla posiciones con r menor, extremo improbable).
    offsets = [0, -10, 10, -20, 20]
    marks = []
    badges = []
    for t, ss in groups.items():
        x = pad + (t - t0).total_seconds() / span * usable
        n = len(ss)
        for i, s in enumerate(ss):
            off = offsets[i % len(offsets)]
            rr = 6 if (i == 0 and n == 1) else 5
            band = s.get("severity")
            fid = s.get("finding_id")
            rules = _esc(s.get("rule_id"))
            hora = _esc(s.get("time"))
            marks.append(
                f'<circle cx="{x:.1f}" cy="{58 + off}" r="{rr}" fill="{_band_color(band)}">'
                f"<title>{_esc(fid)} {rules} @ {hora}</title></circle>"
            )
        if n > 1:
            badges.append(f'<text x="{x:.1f}" y="20" text-anchor="middle" font-size="9" fill="{_MUTED}">×{n}</text>')
    t0_label = t0.strftime("%d/%m %H:%M")
    t1_label = t1.strftime("%d/%m %H:%M") if t1 != t0 else ""
    return (
        f'<svg viewBox="0 0 {width} 88" width="100%" style="max-width:{width}px" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Cronología">'
        f'<text x="0" y="14" font-size="12" font-weight="bold" fill="{_TEXT}">{_esc(title)}</text>'
        f'<line x1="{pad}" y1="58" x2="{width - pad}" y2="58" stroke="#c6d2de" stroke-width="2"/>'
        f'{"".join(marks)}'
        f'{"".join(badges)}'
        f'<text x="{pad}" y="34" font-size="10" fill="{_MUTED}">{_esc(t0_label)}</text>'
        f'<text x="{width - pad}" y="34" font-size="10" fill="{_MUTED}" text-anchor="end">{_esc(t1_label)}</text>'
        f"</svg>"
    )


def mitre_bars_svg(pairs: List[Dict[str, Any]], top: int = 8, width: int = 660) -> str:
    """Barras horizontales por tecnica MITRE (conteo de hallazgos que la citan)."""
    title = "Tecnicas MITRE mas citadas"
    if not pairs:
        return _empty_svg(title, "Sin tecnicas citadas")
    rows = pairs[:top]
    max_count = max(r["count"] for r in rows) or 1
    bar_max = width - 210
    bars = []
    for i, r in enumerate(rows):
        y = 34 + i * 26
        w = max(8, r["count"] / max_count * bar_max)
        bars.append(
            f'<text x="0" y="{y + 12}" font-size="11" fill="{_TEXT}" font-family="monospace">{_esc(r["technique"])}</text>'
            f'<rect x="120" y="{y + 2}" width="{w:.1f}" height="16" rx="3" fill="#0b3a5d"/>'
            f'<text x="{120 + w + 8:.1f}" y="{y + 14}" font-size="11" fill="{_TEXT}">{r["count"]}</text>'
        )
    height = 34 + len(rows) * 26 + 6
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" style="max-width:{width}px" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="{_esc(title)}">'
        f'<text x="0" y="18" font-size="14" font-weight="bold" fill="{_TEXT}">{_esc(title)}</text>'
        f'{"".join(bars)}</svg>'
    )


def _empty_svg(title: str, note: str) -> str:
    return (
        f'<svg viewBox="0 0 330 60" width="330" height="60" xmlns="http://www.w3.org/2000/svg">'
        f'<text x="0" y="18" font-size="14" font-weight="bold" fill="{_TEXT}">{_esc(title)}</text>'
        f'<text x="0" y="40" font-size="11" fill="{_MUTED}">{_esc(note)}</text></svg>'
    )
