// CoveragePanel.tsx - Cobertura del motor: estado de cada regla y por que se omitio (fase B).
import { useEffect, useState } from "react";
import { getCoverage } from "../api";
import type { CoverageResponse } from "../types";

const STATUS_LABELS: Record<string, { label: string; style: string }> = {
  executed: { label: "ejecutada", style: "bg-emerald-100 text-emerald-800" },
  executed_no_findings: { label: "ejecutada sin hallazgos", style: "bg-slate-100 text-slate-600" },
  skipped_disabled: { label: "omitida (deshabilitada)", style: "bg-slate-100 text-slate-500" },
  skipped_missing_fields: {
    label: "omitida (faltan campos)",
    style: "bg-amber-100 text-amber-800",
  },
  insufficient_data: {
    label: "datos insuficientes",
    style: "bg-sky-100 text-sky-800",
  },
  error: { label: "error", style: "bg-red-100 text-red-800" },
};

interface Props {
  sessionId: string;
  sheet: string;
  onError: (msg: string) => void;
}

export function CoveragePanel({ sessionId, sheet, onError }: Props) {
  const [data, setData] = useState<CoverageResponse | null>(null);

  useEffect(() => {
    let cancelled = false;
    getCoverage(sessionId, sheet)
      .then((res) => {
        if (!cancelled) {
          setData(res);
          onError("");
        }
      })
      .catch((e: Error) => {
        if (!cancelled) onError(`No se pudo cargar la cobertura: ${e.message}`);
      });
    return () => {
      cancelled = true;
    };
  }, [sessionId, sheet, onError]);

  if (!data) return null;
  const s = data.summary;

  return (
    <section className="rounded border border-slate-200 bg-white">
      <header className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-3">
        <h2 className="text-sm font-semibold text-slate-800">Cobertura de reglas</h2>
        <span className="text-xs text-slate-500">
          {s.total_rules} reglas · {s.rules_executed} con hallazgos · {s.rules_executed_no_findings} sin
          hallazgos · {s.rules_skipped_missing_fields} sin campos · {s.rules_insufficient_data} con datos
          insuficientes · {s.rules_error} con error · {s.elapsed_ms} ms
        </span>
      </header>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-50 text-xs uppercase text-slate-500">
            <tr>
              <th className="px-4 py-2">Regla</th>
              <th className="px-4 py-2">Estado</th>
              <th className="px-4 py-2">Hallazgos</th>
              <th className="px-4 py-2">Motivo</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {data.coverage.map((c) => {
              const st = STATUS_LABELS[c.status] ?? { label: c.status, style: "bg-slate-100" };
              return (
                <tr key={c.rule_id}>
                  <td className="px-4 py-1.5 font-mono text-xs text-slate-700">
                    {c.rule_id} <span className="font-sans text-slate-400">{c.rule_name}</span>
                  </td>
                  <td className="px-4 py-1.5">
                    <span className={`rounded px-2 py-0.5 text-xs ${st.style}`}>{st.label}</span>
                  </td>
                  <td className="px-4 py-1.5 text-slate-700">{c.findings}</td>
                  <td className="px-4 py-1.5 text-xs text-slate-500">{c.reason ?? "—"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
