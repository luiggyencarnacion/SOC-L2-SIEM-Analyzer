// ReportPanel.tsx - Fase F: informe tecnico completo con estructura jerarquica
// (capitulos y subpuntos: "5. Hallazgos" -> 5.1, 5.2...), edicion/regeneracion
// de secciones, PDF (portada, indice clicable, numeracion, tablas y evidencia)
// y exportaciones (IoCs CSV anti-formulas y hallazgos JSON).
import { useCallback, useEffect, useState } from "react";
import {
  downloadFindingsJson,
  downloadIocsCsv,
  downloadReportPdf,
  editReportSection,
  getReport,
  regenerateReportSection,
  saveReportMeta,
} from "../api";
import type { ReportResponse, ReportSection } from "../types";

interface Props {
  sessionId: string;
  sheet: string;
  onError: (msg: string) => void;
  onOpenEvidence: (logId: string) => void;
}

const LABEL_STYLES: Record<string, string> = {
  Hecho: "bg-emerald-100 text-emerald-800 border-emerald-300",
  Inferencia: "bg-amber-100 text-amber-800 border-amber-300",
  "Hipótesis": "bg-slate-100 text-slate-700 border-slate-300",
};

const SOURCE_STYLES: Record<string, string> = {
  plantilla: "bg-slate-200 text-slate-700",
  ia_validada: "bg-sky-100 text-sky-800",
  manual: "bg-violet-100 text-violet-800",
};

// Convierte los parrafos de una seccion en el texto editable (una linea por
// parrafo, con prefijo opcional de etiqueta).
function sectionToText(s: ReportSection): string {
  return s.paragraphs
    .map((p) => (p.label && p.label !== "Hecho" ? `${p.label}: ${p.text}` : p.text))
    .join("\n");
}

export function ReportPanel({ sessionId, sheet, onError, onOpenEvidence }: Props) {
  const [report, setReport] = useState<ReportResponse | null>(null);
  const [expanded, setExpanded] = useState<string | null>("resumen_ejecutivo");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [metaDraft, setMetaDraft] = useState<{ cliente: string; analista: string }>({ cliente: "", analista: "" });
  const [savingMeta, setSavingMeta] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setReport(null);
    getReport(sessionId, sheet)
      .then((r) => {
        if (!cancelled) {
          setReport(r);
          setMetaDraft({
            cliente: r.meta?.cliente === "(cliente por completar)" ? "" : r.meta?.cliente || "",
            analista: r.meta?.analista === "(analista por completar)" ? "" : r.meta?.analista || "",
          });
        }
      })
      .catch((e: Error) => {
        if (!cancelled) onError(`No se pudo cargar el informe: ${e.message}`);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, sheet]);

  const saveMeta = () => {
    setSavingMeta(true);
    saveReportMeta(sessionId, { cliente: metaDraft.cliente, analista: metaDraft.analista }, sheet)
      .then((r) => {
        setReport((prev) => (prev ? { ...prev, meta: r.meta } : prev));
        onError("");
      })
      .catch((e: Error) => onError(`No se pudieron guardar los datos de portada: ${e.message}`))
      .finally(() => setSavingMeta(false));
  };

  const onDownload = useCallback(
    async (kind: "pdf" | "csv" | "json") => {
      setDownloading(kind);
      try {
        if (kind === "pdf") await downloadReportPdf(sessionId, sheet);
        else if (kind === "csv") await downloadIocsCsv(sessionId, sheet);
        else await downloadFindingsJson(sessionId, sheet);
        onError("");
      } catch (e) {
        onError(`No se pudo descargar: ${(e as Error).message}`);
      } finally {
        setDownloading(null);
      }
    },
    [sessionId, sheet, onError],
  );

  const startEdit = (s: ReportSection) => {
    setEditingId(s.section_id);
    setDraft(sectionToText(s));
  };

  const saveEdit = (s: ReportSection) => {
    setSaving(true);
    editReportSection(sessionId, s.section_id, draft, sheet)
      .then((r) => {
        setReport((prev) =>
          prev
            ? { ...prev, sections: prev.sections.map((x) => (x.section_id === s.section_id ? r.section : x)) }
            : prev,
        );
        setEditingId(null);
        onError("");
      })
      .catch((e: Error) => onError(`No se pudo guardar la edición: ${e.message}`))
      .finally(() => setSaving(false));
  };

  const regenerate = (s: ReportSection) => {
    setSaving(true);
    regenerateReportSection(sessionId, s.section_id, sheet)
      .then((r) => {
        setReport((prev) =>
          prev
            ? { ...prev, sections: prev.sections.map((x) => (x.section_id === s.section_id ? r.section : x)) }
            : prev,
        );
        setEditingId(null);
        onError("");
      })
      .catch((e: Error) => onError(`No se pudo regenerar la sección: ${e.message}`))
      .finally(() => setSaving(false));
  };

  if (!report) {
    return <p className="text-sm text-slate-500">Cargando informe…</p>;
  }

  const matches = (s: ReportSection) =>
    !filter || s.title.toLowerCase().includes(filter.toLowerCase()) || s.section_id.includes(filter);

  const childrenOf = new Map<string, ReportSection[]>();
  const parents: ReportSection[] = [];
  for (const s of report.sections) {
    if (s.parent) {
      const list = childrenOf.get(s.parent) ?? [];
      list.push(s);
      childrenOf.set(s.parent, list);
    } else {
      parents.push(s);
    }
  }
  const visibleParents = parents.filter(
    (p) => matches(p) || (childrenOf.get(p.section_id) ?? []).some(matches),
  );

  // --- cuerpo compartido: parrafos, tablas, edicion y acciones de una seccion ---
  const renderBody = (s: ReportSection) => (
    <div className="border-t border-slate-100 px-4 py-3 space-y-3">
      {editingId === s.section_id ? (
        <div className="space-y-2">
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            rows={Math.min(14, Math.max(4, draft.split("\n").length + 1))}
            className="w-full rounded border border-slate-300 px-3 py-2 text-sm font-mono"
          />
          <p className="text-xs text-slate-500">
            Una línea por párrafo. Prefijo opcional de etiqueta: <code>Hecho:</code>,{" "}
            <code>Inferencia:</code> o <code>Hipótesis:</code> (sin prefijo = Hecho). Máx. 20.000 caracteres.
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => saveEdit(s)}
              disabled={saving}
              className="rounded bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white px-3 py-1.5 text-xs"
            >
              {saving ? "Guardando…" : "Guardar edición"}
            </button>
            <button
              onClick={() => setEditingId(null)}
              disabled={saving}
              className="rounded bg-slate-200 hover:bg-slate-300 text-slate-700 px-3 py-1.5 text-xs"
            >
              Cancelar
            </button>
          </div>
        </div>
      ) : (
        <>
          {s.paragraphs.map((p, i) => (
            <p key={i} className="text-sm text-slate-700 leading-relaxed">
              <span
                className={`mr-2 inline-block rounded border px-1.5 py-0.5 text-[10px] font-medium ${
                  LABEL_STYLES[p.label] ?? "bg-slate-100 text-slate-700 border-slate-300"
                }`}
              >
                {p.label}
              </span>
              <span
                className={`mr-2 inline-block rounded px-1 text-[10px] ${
                  SOURCE_STYLES[p.source] ?? "bg-slate-200 text-slate-700"
                }`}
              >
                {p.source === "ia_validada" ? "IA validada" : p.source}
              </span>
              {p.text}
              {p.citations.length > 0 && (
                <span className="ml-2 inline-flex flex-wrap gap-1 align-middle">
                  {p.citations.map((c) => (
                    <button
                      key={c}
                      onClick={(e) => {
                        e.stopPropagation();
                        onOpenEvidence(c);
                      }}
                      className="rounded bg-sky-50 border border-sky-200 px-1.5 py-0.5 text-[10px] font-mono text-sky-700 hover:bg-sky-100"
                      title={`Abrir evidencia ${c} en la tabla de eventos`}
                    >
                      {c}
                    </button>
                  ))}
                </span>
              )}
            </p>
          ))}

          {s.tables.map((t) => (
            <div key={t.table_id} className="overflow-x-auto">
              <p className="text-xs font-semibold text-slate-600 mb-1">{t.title}</p>
              {t.rows.length === 0 ? (
                <p className="text-xs italic text-slate-500">Sin filas.</p>
              ) : (
                <table className="w-full text-xs border border-slate-200">
                  <thead>
                    <tr className="bg-slate-50">
                      {t.columns.map((c) => (
                        <th key={c.key} className="border border-slate-200 px-2 py-1 text-left font-medium text-slate-600">
                          {c.label}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {t.rows.map((row, ri) => (
                      <tr key={ri} className="odd:bg-white even:bg-slate-50">
                        {t.columns.map((c) => {
                          const v = row[c.key];
                          const isLogIdCol = c.key === "log_id";
                          const isEvidenceCol = c.key === "evidence" && typeof v === "string" && v.includes("EVT-");
                          if (isLogIdCol || isEvidenceCol) {
                            const target = isLogIdCol ? String(v) : String(v).split(",")[0].trim();
                            return (
                              <td key={c.key} className="border border-slate-200 px-2 py-1 align-top">
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    onOpenEvidence(target);
                                  }}
                                  className="font-mono text-sky-700 hover:underline"
                                >
                                  {String(v)}
                                </button>
                              </td>
                            );
                          }
                          return (
                            <td key={c.key} className="border border-slate-200 px-2 py-1 text-slate-700 align-top">
                              {v === null || v === undefined || v === "" ? "—" : String(v)}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          ))}

          <div className="flex gap-2 pt-1">
            {s.editable && (
              <button
                onClick={() => startEdit(s)}
                disabled={saving}
                className="rounded bg-slate-700 hover:bg-slate-600 text-white px-3 py-1.5 text-xs"
              >
                Editar sección
              </button>
            )}
            {s.edited && (
              <button
                onClick={() => regenerate(s)}
                disabled={saving}
                className="rounded bg-amber-500 hover:bg-amber-600 disabled:opacity-50 text-white px-3 py-1.5 text-xs"
              >
                Regenerar (restaurar plantilla)
              </button>
            )}
          </div>
        </>
      )}
    </div>
  );

  // --- cabecera comun (numero, titulo, badges) ---
  const renderHeader = (s: ReportSection, nested: boolean) => {
    const isOpen = expanded === s.section_id;
    return (
      <header
        className={`flex items-center gap-2 ${nested ? "px-3 py-2" : "px-4 py-3"} cursor-pointer select-none`}
        onClick={() => setExpanded(isOpen ? null : s.section_id)}
      >
        <span className={`text-slate-400 font-mono ${nested ? "text-[11px] w-10" : "text-xs w-8"}`}>{s.number}</span>
        <h3 className={`flex-1 ${nested ? "text-[13px] font-medium text-slate-700" : "text-sm font-semibold text-slate-800"}`}>
          {s.title}
        </h3>
        {s.edited && (
          <span className="rounded px-1.5 py-0.5 text-[10px] bg-violet-100 text-violet-800">
            editada {s.edited_at ? `· ${new Date(s.edited_at).toLocaleString()}` : ""}
          </span>
        )}
        {s.tables.length > 0 && (
          <span className="rounded px-1.5 py-0.5 text-[10px] bg-slate-100 text-slate-600">
            {s.tables.length} tabla(s) · {s.tables.reduce((n, t) => n + t.rows.length, 0)} filas
          </span>
        )}
        <span className="text-slate-400 text-xs">{isOpen ? "▼" : "▶"}</span>
      </header>
    );
  };

  // --- seccion nivel 2 (subpunto de Hallazgos/Incidentes) ---
  const renderChild = (s: ReportSection) => {
    const isOpen = expanded === s.section_id;
    return (
      <section key={s.section_id} className="rounded border border-slate-200 bg-slate-50/60">
        {renderHeader(s, true)}
        {isOpen && renderBody(s)}
      </section>
    );
  };

  // --- seccion nivel 1 (capitulo; los contenedores anidan sus subpuntos) ---
  const renderParent = (s: ReportSection) => {
    const isOpen = expanded === s.section_id;
    const children = childrenOf.get(s.section_id) ?? [];
    return (
      <section key={s.section_id} className="rounded border border-slate-200 bg-white">
        {renderHeader(s, false)}
        {isOpen && (
          <div className={s.kind === "contenedor" ? "space-y-2 border-t border-slate-100 px-4 py-3" : ""}>
            {s.kind === "contenedor" ? (
              <>
                {s.paragraphs.map((p, i) => (
                  <p key={i} className="text-xs text-slate-500">{p.text}</p>
                ))}
                {children.map(renderChild)}
              </>
            ) : (
              <>
                {s.cards && s.cards.length > 0 && (
                  <div className="flex flex-wrap gap-2 py-2">
                    {s.cards.map((c) => (
                      <div key={c.label} className="rounded border border-slate-200 bg-slate-50 px-3 py-2">
                        <div className="text-lg font-bold text-sky-800">{c.value}</div>
                        <div className="text-[11px] text-slate-600">{c.label}</div>
                        {c.hint && <div className="text-[10px] text-slate-400">{c.hint}</div>}
                      </div>
                    ))}
                  </div>
                )}
                {renderBody(s)}
              </>
            )}
          </div>
        )}
      </section>
    );
  };

  return (
    <div className="space-y-4">
      {/* --- Acciones del informe --- */}
      <section className="rounded border border-slate-200 bg-white px-4 py-3">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-sm font-semibold text-slate-800">
            Informe técnico · {report.total_sections} secciones · hoja <span className="font-mono">{report.sheet}</span>
          </h2>
          <span className="text-xs text-slate-500">
            Generado: {new Date(report.generated_at).toLocaleString()}
          </span>
          <div className="ml-auto flex flex-wrap gap-2">
            <button
              onClick={() => onDownload("pdf")}
              disabled={downloading !== null}
              className="rounded bg-sky-600 hover:bg-sky-700 disabled:opacity-50 text-white px-3 py-1.5 text-xs"
            >
              {downloading === "pdf" ? "Generando PDF…" : "Descargar PDF"}
            </button>
            <button
              onClick={() => onDownload("csv")}
              disabled={downloading !== null}
              className="rounded bg-slate-700 hover:bg-slate-600 disabled:opacity-50 text-white px-3 py-1.5 text-xs"
            >
              {downloading === "csv" ? "Generando…" : "IoCs CSV"}
            </button>
            <button
              onClick={() => onDownload("json")}
              disabled={downloading !== null}
              className="rounded bg-slate-700 hover:bg-slate-600 disabled:opacity-50 text-white px-3 py-1.5 text-xs"
            >
              {downloading === "json" ? "Generando…" : "Hallazgos JSON"}
            </button>
          </div>
        </div>
        <p className="mt-2 text-xs text-slate-500">
          El PDF incluye portada con cliente y analista, índice clicable a 2 niveles con números de página,
          hallazgos en tarjetas de 2 columnas, cronologías por incidente, tablas con cabecera repetida y
          evidencias completas en el Anexo C (horizontal). Los párrafos editados se marcan{" "}
          <span className={`rounded px-1 text-[10px] ${SOURCE_STYLES.manual}`}>manual</span>.
        </p>
        {/* --- Portada editable: cliente y analista --- */}
        <div className="mt-3 flex flex-wrap items-end gap-3 border-t border-slate-100 pt-3">
          <label className="flex flex-col gap-1">
            <span className="text-[11px] font-medium text-slate-600">Cliente (portada del PDF)</span>
            <input
              value={metaDraft.cliente}
              onChange={(e) => setMetaDraft({ ...metaDraft, cliente: e.target.value })}
              placeholder="Nombre del cliente"
              className="rounded border border-slate-300 px-2 py-1.5 text-xs w-56"
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-[11px] font-medium text-slate-600">Analista</span>
            <input
              value={metaDraft.analista}
              onChange={(e) => setMetaDraft({ ...metaDraft, analista: e.target.value })}
              placeholder="Nombre del analista"
              className="rounded border border-slate-300 px-2 py-1.5 text-xs w-56"
            />
          </label>
          <button
            onClick={saveMeta}
            disabled={savingMeta}
            className="rounded bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white px-3 py-1.5 text-xs"
          >
            {savingMeta ? "Guardando…" : "Guardar portada"}
          </button>
          {report.file_name && (
            <span className="text-[11px] text-slate-500">Archivo: <strong>{report.file_name}</strong></span>
          )}
        </div>
      </section>

      {/* --- Buscador de secciones --- */}
      <div className="flex items-center gap-2">
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filtrar secciones por título o id…"
          className="flex-1 rounded border border-slate-300 px-3 py-1.5 text-sm"
        />
        <span className="text-xs text-slate-500">{visibleParents.length} capítulos</span>
      </div>

      {/* --- Secciones jerarquicas --- */}
      {visibleParents.map(renderParent)}
    </div>
  );
}
