// MappingEditor.tsx - Vista previa de la hoja + mapeo manual columna->campo.
import { useMemo, useState } from "react";
import { analyzeSheet } from "../api";
import type {
  AnalyzeResponse,
  MappingEntry,
  SheetPreview,
  UploadResponse,
} from "../types";
import { UNIVERSAL_FIELDS } from "../types";

export function MappingEditor({
  session,
  sheet,
  onSheetChange,
  onAnalyzed,
  onError,
}: {
  session: UploadResponse;
  sheet: string;
  onSheetChange: (s: string) => void;
  onAnalyzed: (total: number, quality: AnalyzeResponse["quality"], aliases: AnalyzeResponse["aliases"]) => void;
  onError: (msg: string) => void;
}) {
  const sheetPreview: SheetPreview | undefined = session.sheets.find((s) => s.name === sheet);
  const mappingDef = session.mappings.find((m) => m.sheet === sheet);
  const [headerRow, setHeaderRow] = useState<number>(mappingDef?.header_row ?? 1);
  const [entries, setEntries] = useState<MappingEntry[]>(
    (mappingDef?.suggestions ?? []).map((s) => ({ column: s.column, field: s.field })),
  );

  const preview = useMemo(() => sheetPreview?.preview_rows ?? [], [sheetPreview]);

  const update = (idx: number, field: string | null) => {
    setEntries((prev) => prev.map((e, i) => (i === idx ? { ...e, field } : e)));
    onError("");
  };

  const run = async () => {
    if (!session || !sheet) return;
    onError("");
    try {
      const res = await analyzeSheet({
        sessionId: session.session_id,
        sheet,
        headerRow,
        mapping: entries,
      });
      onAnalyzed(res.total_rows, res.quality, res.aliases);
    } catch (e) {
      onError(e instanceof Error ? e.message : "Error al analizar la hoja");
    }
  };

  if (!sheetPreview || !mappingDef) {
    return <div className="bg-white rounded border p-6 text-sm">Hoja no encontrada.</div>;
  }

  return (
    <div className="space-y-4">
      <div className="bg-white rounded-lg border border-slate-200 p-6 space-y-4">
        <div className="flex flex-wrap items-center gap-4">
          <div>
            <label className="text-sm font-medium block mb-1">Hoja</label>
            <select
              value={sheet}
              onChange={(e) => {
                onSheetChange(e.target.value);
                const md = session.mappings.find((m) => m.sheet === e.target.value);
                setHeaderRow(md?.header_row ?? 1);
                setEntries((md?.suggestions ?? []).map((s) => ({ column: s.column, field: s.field })));
              }}
              className="rounded border border-slate-300 px-3 py-1.5 text-sm"
            >
              {session.sheets.map((s) => (
                <option key={s.name} value={s.name}>
                  {s.name} — {s.data_rows} filas × {s.data_columns} columnas
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-sm font-medium block mb-1">Fila de cabecera</label>
            <input
              type="number"
              min={1}
              value={headerRow}
              onChange={(e) => setHeaderRow(Math.max(1, Number(e.target.value) || 1))}
              className="rounded border border-slate-300 px-3 py-1.5 text-sm w-24"
            />
          </div>
          <button
            onClick={() => void run()}
            className="ml-auto rounded bg-emerald-600 hover:bg-emerald-500 text-white px-5 py-2 text-sm font-medium"
          >
            Normalizar y ver tabla
          </button>
        </div>

        <div className="text-xs text-slate-500">
          Confianza del mapeo automático: <strong>{Math.round(mappingDef.confidence * 100)}%</strong>
        </div>

        <div className="overflow-x-auto max-h-56 border rounded">
          <table className="min-w-full text-xs border-collapse">
            <thead className="bg-slate-50 sticky top-0">
              <tr>
                {sheetPreview.columns.map((c) => (
                  <th key={c} className="border-b px-2 py-1.5 text-left font-medium whitespace-nowrap">
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {preview.map((row, i) => (
                <tr key={i} className={i % 2 ? "bg-slate-50" : ""}>
                  {sheetPreview.columns.map((c) => (
                    <td key={c} className="px-2 py-1 whitespace-nowrap max-w-64 truncate" title={String(row[c] ?? "")}>
                      {row[c] === null || row[c] === undefined ? <span className="text-slate-400">—</span> : String(row[c])}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="bg-white rounded-lg border border-slate-200 p-6">
        <h3 className="text-sm font-semibold mb-3">Mapeo columna → campo universal</h3>
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-slate-500 border-b">
                <th className="py-1.5 pr-4">Columna {sheet && `(${mappingDef.sheet})`}</th>
                <th className="py-1.5 pr-4">Campo</th>
                <th className="py-1.5 pr-4">Confianza</th>
                <th className="py-1.5">Motivo</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry, idx) => {
                const sug = mappingDef.suggestions[idx];
                return (
                  <tr key={entry.column} className="border-b border-slate-100">
                    <td className="py-1.5 pr-4 font-medium">{entry.column}</td>
                    <td className="py-1.5 pr-4">
                      <select
                        value={entry.field ?? ""}
                        onChange={(e) => update(idx, e.target.value || null)}
                        className="rounded border border-slate-300 px-2 py-1 text-xs min-w-36"
                      >
                        <option value="">(sin mapear)</option>
                        {UNIVERSAL_FIELDS.map((f) => (
                          <option key={f} value={f}>
                            {f}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className="py-1.5 pr-4 text-xs">
                      {sug ? `${Math.round(sug.confidence * 100)}%` : "—"}
                    </td>
                    <td className="py-1.5 text-xs text-slate-500">{sug?.rationale ?? "asignacion manual"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
