// QualityPanel.tsx - Nulos, duplicados, timestamp y tipos mezclados.
import type { DataQualityReport } from "../types";

export function QualityPanel({ quality }: { quality: DataQualityReport }) {
  const tsSum = quality.timestamp;
  const mixed = quality.mixed_type_columns;

  return (
    <div className="bg-white rounded-lg border border-slate-200 p-6 space-y-5">
      <h3 className="text-sm font-semibold">Calidad de datos ({quality.total_rows.toLocaleString("es")} filas)</h3>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
        <Kpi label="Timestamps mapeados" value={tsSum.total - tsSum.missing} tone="ok" />
        <Kpi label="Sin timestamp" value={tsSum.missing} tone={tsSum.missing ? "warn" : "ok"} />
        <Kpi label="Timestamp inválidos" value={tsSum.invalid} tone={tsSum.invalid ? "warn" : "ok"} />
        <Kpi label="Duplicados Log_ID" value={quality.duplicate_log_ids.length} tone={quality.duplicate_log_ids.length ? "warn" : "ok"} />
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full text-xs border-collapse">
          <thead>
            <tr className="bg-slate-50 text-left">
              <th className="border-b px-2 py-1.5">Campo</th>
              <th className="border-b px-2 py-1.5">Con valor</th>
              <th className="border-b px-2 py-1.5">Nulos</th>
              <th className="border-b px-2 py-1.5">%</th>
              <th className="border-b px-2 py-1.5">Distintos</th>
            </tr>
          </thead>
          <tbody>
            {quality.columns.map((c) => (
              <tr key={c.column} className="border-b border-slate-100">
                <td className="px-2 py-1 font-medium">{c.column}</td>
                <td className="px-2 py-1">{c.populated}</td>
                <td className={`px-2 py-1 ${c.nulls > 0 ? "text-amber-700" : ""}`}>{c.nulls}</td>
                <td className="px-2 py-1">{c.null_percent}%</td>
                <td className="px-2 py-1">{c.distinct ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="text-[11px] text-slate-500 mt-1">
          Counts de alias estan en el panel Aliases; los campos `*_extraidos_de_texto` provienen de regex sobre texto libre.
        </p>
      </div>

      <div className="flex flex-wrap gap-3 text-xs">
        {Object.entries(quality.result_distribution).map(([k, v]) => (
          <span key={k} className="rounded bg-slate-100 px-2 py-1">
            result_norm={k}: <strong>{v}</strong>
          </span>
        ))}
        {tsSum.offset > 0 && <span className="rounded bg-slate-100 px-2 py-1">con offset horario: {tsSum.offset}</span>}
        {tsSum.wall > 0 && <span className="rounded bg-slate-100 px-2 py-1">hora de pared (sin zona): {tsSum.wall}</span>}
        {mixed.length > 0 && (
          <span className="rounded bg-amber-100 text-amber-800 px-2 py-1">
            Tipos mezclados: {mixed.join(", ")}
          </span>
        )}
      </div>
    </div>
  );
}

function Kpi({ label, value, tone }: { label: string; value: number; tone: "ok" | "warn" }) {
  return (
    <div className={`rounded border px-3 py-2 ${tone === "warn" ? "border-amber-300 bg-amber-50" : "border-emerald-200 bg-emerald-50"}`}>
      <div className="text-lg font-semibold">{value.toLocaleString("es")}</div>
      <div className="text-slate-600">{label}</div>
    </div>
  );
}
