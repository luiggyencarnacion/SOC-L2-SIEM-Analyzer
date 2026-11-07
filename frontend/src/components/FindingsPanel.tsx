// FindingsPanel.tsx - Hallazgos del motor determinista con evidencia por Log_ID (fase B).
// Cada hallazgo muestra severidad, MITRE, entidades y afirmaciones Hecho/Inferencia/Hipotesis.
// Los Log_ID de evidencia son clickeables: abren la fila cruda en la tabla de eventos.
import { useEffect, useState } from "react";
import { getFindings } from "../api";
import type { FindingsResponse, Finding } from "../types";

const SEVERITY_STYLES: Record<string, string> = {
  Crítico: "bg-red-100 text-red-800 border-red-300",
  Alto: "bg-orange-100 text-orange-800 border-orange-300",
  Medio: "bg-amber-100 text-amber-800 border-amber-300",
  Bajo: "bg-slate-100 text-slate-700 border-slate-300",
};

const SEVERITY_ORDER = ["Crítico", "Alto", "Medio", "Bajo"];

interface Props {
  sessionId: string;
  sheet: string;
  onError: (msg: string) => void;
  onOpenEvidence: (logId: string) => void;
}

export function FindingsPanel({ sessionId, sheet, onError, onOpenEvidence }: Props) {
  const [data, setData] = useState<FindingsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    getFindings(sessionId, sheet, severityFilter || undefined)
      .then((res) => {
        if (!cancelled) {
          setData(res);
          onError("");
        }
      })
      .catch((e: Error) => {
        if (!cancelled) onError(`No se pudieron cargar los hallazgos: ${e.message}`);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [sessionId, sheet, severityFilter, onError]);

  if (loading) return <p className="text-sm text-slate-500">Cargando hallazgos…</p>;
  if (!data) return null;

  const sevCounts = data.summary.findings_by_severity ?? {};

  return (
    <section className="rounded border border-slate-200 bg-white">
      <header className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-3">
        <h2 className="text-sm font-semibold text-slate-800">Hallazgos de detección</h2>
        <span className="text-xs text-slate-500">
          {data.total} hallazgo(s) · motor determinista · evidencia por Log_ID
        </span>
        <div className="ml-auto flex items-center gap-2 text-xs">
          {SEVERITY_ORDER.filter((s) => sevCounts[s]).map((s) => (
            <button
              key={s}
              onClick={() => setSeverityFilter(severityFilter === s ? "" : s)}
              className={`rounded border px-2 py-0.5 ${
                severityFilter === s ? SEVERITY_STYLES[s] : "border-slate-300 text-slate-600 hover:bg-slate-50"
              }`}
            >
              {s} ({sevCounts[s]})
            </button>
          ))}
          {severityFilter && (
            <button onClick={() => setSeverityFilter("")} className="text-slate-500 underline">
              quitar filtro
            </button>
          )}
        </div>
      </header>

      {data.total === 0 ? (
        <p className="px-4 py-6 text-sm text-slate-500">
          No hay hallazgos para este filtro. <strong>No hay evidencia en los logs proporcionados.</strong>
        </p>
      ) : (
        <ul className="divide-y divide-slate-100">
          {data.findings.map((f) => (
            <FindingCard
              key={f.finding_id}
              finding={f}
              expanded={expanded === f.finding_id}
              onToggle={() => setExpanded(expanded === f.finding_id ? null : f.finding_id)}
              onOpenEvidence={onOpenEvidence}
            />
          ))}
        </ul>
      )}
    </section>
  );
}

function FindingCard({
  finding,
  expanded,
  onToggle,
  onOpenEvidence,
}: {
  finding: Finding;
  expanded: boolean;
  onToggle: () => void;
  onOpenEvidence: (logId: string) => void;
}) {
  const style = SEVERITY_STYLES[finding.severity] ?? SEVERITY_STYLES.Bajo;
  const omitted = finding.evidence_omitted > 0;

  return (
    <li className="px-4 py-3">
      <div className="flex flex-wrap items-start gap-2">
        <span className={`rounded border px-2 py-0.5 text-xs font-medium ${style}`}>
          {finding.severity}
        </span>
        {finding.band !== undefined && (
          <span className="rounded bg-slate-100 px-2 py-0.5 text-xs text-slate-600" title="Score automático (fase C)">
            {finding.score} · {finding.band}
          </span>
        )}
        {finding.override && (
          <span className="rounded bg-purple-100 px-2 py-0.5 text-xs text-purple-900" title={finding.override.reason}>
            Override manual: {finding.override.classification}
          </span>
        )}
        <button onClick={onToggle} className="text-left text-sm font-semibold text-slate-800 hover:underline">
          {finding.finding_id} · {finding.rule_id} — {finding.rule_name}
        </button>
        <span className="text-xs text-slate-500">{finding.category}</span>
        {finding.mitre.length > 0 && (
          <span className="text-xs text-indigo-700">{finding.mitre.join(", ")}</span>
        )}
        <span className="ml-auto text-xs text-slate-400">
          {finding.total_events_matched} evento(s)
          {finding.time_range.start
            ? ` · ${finding.time_range.start.replace("T", " ")} → ${finding.time_range.end?.replace("T", " ")}`
            : ""}
        </span>
      </div>

      {expanded && (
        <div className="mt-3 space-y-3 text-sm text-slate-700">
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <h4 className="text-xs font-semibold uppercase text-slate-400">Qué detecta</h4>
              <p className="mt-1">{finding.description}</p>
            </div>
            <div>
              <h4 className="text-xs font-semibold uppercase text-slate-400">Justificación</h4>
              <p className="mt-1">{finding.rationale}</p>
            </div>
          </div>

          <StatementsBlock finding={finding} />

          <div>
            <h4 className="text-xs font-semibold uppercase text-slate-400">
              Evidencia ({finding.total_evidence} evento(s))
            </h4>
            <div className="mt-1 flex flex-wrap gap-1.5">
              {finding.evidence_log_ids.map((lid) => (
                <button
                  key={lid}
                  onClick={() => onOpenEvidence(lid)}
                  className="rounded bg-slate-100 px-2 py-0.5 font-mono text-xs text-slate-700 hover:bg-indigo-100 hover:text-indigo-800"
                  title="Abrir fila cruda en la tabla de eventos"
                >
                  {lid}
                </button>
              ))}
              {omitted && (
                <span className="text-xs text-slate-400">
                  +{finding.evidence_omitted} más (limitados por configuración de la regla)
                </span>
              )}
            </div>
          </div>

          <EntitiesBlock finding={finding} />
        </div>
      )}
    </li>
  );
}

function StatementsBlock({ finding }: { finding: Finding }) {
  const { hecho, inferencia, hipotesis } = finding.statements;
  return (
    <div className="space-y-1">
      {hecho.map((s, i) => (
        <p key={`h${i}`} className="rounded bg-emerald-50 px-2 py-1 text-emerald-900">
          <strong className="mr-1 text-[10px] uppercase">Hecho</strong> {s}
        </p>
      ))}
      {inferencia.map((s, i) => (
        <p key={`i${i}`} className="rounded bg-amber-50 px-2 py-1 text-amber-900">
          <strong className="mr-1 text-[10px] uppercase">Inferencia</strong> {s}
        </p>
      ))}
      {hipotesis.map((s, i) => (
        <p key={`p${i}`} className="rounded bg-slate-100 px-2 py-1 text-slate-600">
          <strong className="mr-1 text-[10px] uppercase">Hipótesis</strong> {s}
        </p>
      ))}
    </div>
  );
}

function EntitiesBlock({ finding }: { finding: Finding }) {
  const e = finding.entities;
  const rows: [string, string[]][] = [
    ["Usuarios", e.users],
    ["Hosts", e.hosts],
    ["IPs origen", e.source_ips],
    ["Destinos", e.destinations],
  ];
  return (
    <div className="grid grid-cols-2 gap-2 text-xs md:grid-cols-4">
      {rows.map(([label, values]) => (
        <div key={label} className="rounded bg-slate-50 px-2 py-1.5">
          <span className="font-semibold text-slate-500">{label}</span>
          <p className="mt-0.5 text-slate-700">
            {values.length === 0 ? "—" : values.slice(0, 4).join(", ")}
            {values.length > 4 ? ` +${values.length - 4}` : ""}
          </p>
        </div>
      ))}
    </div>
  );
}
