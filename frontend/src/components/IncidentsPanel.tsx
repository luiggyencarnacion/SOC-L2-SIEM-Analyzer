// IncidentsPanel.tsx - Incidentes correlacionados con timeline, IoCs, MITRE,
// kill chain y override manual con motivo obligatorio (fase C).
// Toda la evidencia cita Log_ID clickeables que abren la fila cruda en la tabla.
import { useEffect, useState } from "react";
import { createOverride, getIncidents } from "../api";
import type { CorrelationResponse, Incident, OverrideInfo } from "../types";
import { OVERRIDE_CLASSIFICATIONS } from "../types";

const BAND_STYLES: Record<string, string> = {
  Crítico: "bg-red-100 text-red-800 border-red-300",
  Alto: "bg-orange-100 text-orange-800 border-orange-300",
  Medio: "bg-amber-100 text-amber-800 border-amber-300",
  Bajo: "bg-slate-100 text-slate-700 border-slate-300",
};

const IOC_LABELS: Record<string, string> = {
  ips: "IPs",
  domains: "Dominios",
  urls: "URLs",
  files: "Archivos/rutas",
  shares: "Shares",
  services_tasks: "Servicios/tareas",
  accounts: "Cuentas",
  hashes: "Hashes",
};

interface Props {
  sessionId: string;
  sheet: string;
  onError: (msg: string) => void;
  onOpenEvidence: (logId: string) => void;
}

export function IncidentsPanel({ sessionId, sheet, onError, onOpenEvidence }: Props) {
  const [data, setData] = useState<CorrelationResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    getIncidents(sessionId, sheet)
      .then((res) => {
        setData(res);
        onError("");
      })
      .catch((e: Error) => onError(`No se pudieron cargar los incidentes: ${e.message}`))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    getIncidents(sessionId, sheet)
      .then((res) => {
        if (!cancelled) {
          setData(res);
          onError("");
        }
      })
      .catch((e: Error) => {
        if (!cancelled) onError(`No se pudieron cargar los incidentes: ${e.message}`);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, sheet]);

  if (loading && !data) return <p className="text-sm text-slate-500">Cargando incidentes…</p>;
  if (!data) return null;

  const bandCounts = data.summary.incidents_by_band ?? {};

  return (
    <section className="rounded border border-slate-200 bg-white">
      <header className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-3">
        <h2 className="text-sm font-semibold text-slate-800">Incidentes correlacionados</h2>
        <span className="text-xs text-slate-500">
          {data.summary.total_incidents} incidente(s) · ventana de {data.summary.window_minutes} min ·
          agrupación por usuario/IP de origen/destino compartidos (el host nunca agrupa solo)
        </span>
        <div className="ml-auto flex items-center gap-2 text-xs">
          {Object.entries(bandCounts).map(([band, n]) => (
            <span key={band} className={`rounded border px-2 py-0.5 ${BAND_STYLES[band] ?? BAND_STYLES.Bajo}`}>
              {band} ({n})
            </span>
          ))}
        </div>
      </header>

      {data.incidents.length === 0 ? (
        <p className="px-4 py-6 text-sm text-slate-500">
          No hay incidentes correlacionados. <strong>No hay evidencia en los logs proporcionados.</strong>
        </p>
      ) : (
        <ul className="divide-y divide-slate-100">
          {data.incidents.map((inc) => (
            <IncidentCard
              key={inc.incident_id}
              incident={inc}
              expanded={expanded === inc.incident_id}
              onToggle={() => setExpanded(expanded === inc.incident_id ? null : inc.incident_id)}
              onOpenEvidence={onOpenEvidence}
              onOverride={(classification, reason) =>
                createOverride(sessionId, "incident", inc.incident_id, classification, reason).then(load)
              }
            />
          ))}
        </ul>
      )}

      {data.relations.length > 0 && (
        <footer className="border-t border-slate-200 px-4 py-3 text-xs text-slate-600">
          <h3 className="font-semibold text-slate-700">Cruces entre cadenas independientes</h3>
          <ul className="mt-1 space-y-1">
            {data.relations.map((rel, i) => (
              <li key={i}>
                <span className="font-mono">{rel.incidents.join(" ↔ ")}</span> — {rel.conclusion} (
                {rel.shared_hosts.join(", ")})
              </li>
            ))}
          </ul>
        </footer>
      )}
    </section>
  );
}

function IncidentCard({
  incident,
  expanded,
  onToggle,
  onOpenEvidence,
  onOverride,
}: {
  incident: Incident;
  expanded: boolean;
  onToggle: () => void;
  onOpenEvidence: (logId: string) => void;
  onOverride: (classification: string, reason: string) => Promise<unknown>;
}) {
  const style = BAND_STYLES[incident.band] ?? BAND_STYLES.Bajo;
  const [showForm, setShowForm] = useState(false);

  return (
    <li className="px-4 py-3">
      <div className="flex flex-wrap items-start gap-2">
        <span className={`rounded border px-2 py-0.5 text-xs font-medium ${style}`}>
          {incident.band} · {incident.score}
        </span>
        <button onClick={onToggle} className="text-left text-sm font-semibold text-slate-800 hover:underline">
          {incident.incident_id} · {incident.title}
        </button>
        {incident.mitre.length > 0 && (
          <span className="text-xs text-indigo-700">{incident.mitre.join(", ")}</span>
        )}
        <span className="ml-auto text-xs text-slate-400">
          {incident.findings.length} hallazgo(s)
          {incident.time_range.start
            ? ` · ${incident.time_range.start.replace("T", " ")} → ${incident.time_range.end?.replace("T", " ")}`
            : ""}
        </span>
      </div>

      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs">
        {incident.kill_chain_phases.map((p) => (
          <span key={p} className="rounded bg-indigo-50 px-2 py-0.5 text-indigo-800">
            {p}
          </span>
        ))}
        {incident.override && (
          <span className="rounded bg-purple-100 px-2 py-0.5 text-purple-900">
            Override manual: {incident.override.classification}
          </span>
        )}
        <button
          onClick={() => setShowForm(!showForm)}
          className="ml-auto rounded border border-slate-300 px-2 py-0.5 text-slate-600 hover:bg-slate-50"
        >
          {incident.override ? "Editar clasificación manual" : "Clasificar manualmente"}
        </button>
      </div>

      {showForm && (
        <OverrideForm
          existing={incident.override}
          onSubmit={(classification, reason) => onOverride(classification, reason).then(() => setShowForm(false))}
        />
      )}

      {expanded && (
        <div className="mt-3 space-y-3 text-sm text-slate-700">
          <div>
            <h4 className="text-xs font-semibold uppercase text-slate-400">
              Timeline ({incident.timeline.length} paso/pasos)
            </h4>
            <ol className="mt-1 space-y-1 border-l-2 border-slate-200 pl-3">
              {incident.timeline.map((t, i) => (
                <li key={`${t.finding_id}-${i}`} className="text-xs">
                  <span className="font-mono text-slate-500">{t.time?.replace("T", " ") ?? "sin hora"}</span>{" "}
                  · <span className="font-semibold">{t.rule_id}</span> {t.rule_name} ·{" "}
                  <span className="text-slate-500">{t.severity} ({t.score})</span>
                  <span className="ml-2 flex flex-wrap gap-1">
                    {t.evidence_log_ids.map((lid) => (
                      <button
                        key={lid}
                        onClick={() => onOpenEvidence(lid)}
                        className="rounded bg-slate-100 px-1.5 py-0 font-mono text-[10px] text-slate-700 hover:bg-indigo-100 hover:text-indigo-800"
                        title="Abrir fila cruda en la tabla de eventos"
                      >
                        {lid}
                      </button>
                    ))}
                  </span>
                </li>
              ))}
            </ol>
          </div>

          <IoCsBlock incident={incident} />
          <AssetsBlock incident={incident} />

          <div>
            <h4 className="text-xs font-semibold uppercase text-slate-400">Justificación de agrupación</h4>
            <p className="mt-1 text-xs">{incident.grouping.justification}</p>
            <p className="mt-1 text-xs text-slate-500">
              Entidades compartidas:{" "}
              {Object.entries(incident.grouping.shared_entities).length === 0
                ? "—"
                : Object.entries(incident.grouping.shared_entities)
                    .map(([k, v]) => `${k}: ${v.slice(0, 3).join(", ")}`)
                    .join(" · ")}
              {incident.grouping.max_gap_minutes !== null &&
                ` · distancia máxima entre hallazgos: ${incident.grouping.max_gap_minutes} min`}
            </p>
            {incident.grouping.alias_notes.map((n, i) => (
              <p key={i} className="mt-1 rounded bg-amber-50 px-2 py-1 text-xs text-amber-900">
                <strong className="mr-1 text-[10px] uppercase">Inferencia</strong> {n}
              </p>
            ))}
          </div>
        </div>
      )}
    </li>
  );
}

function IoCsBlock({ incident }: { incident: Incident }) {
  const entries = Object.entries(incident.iocs).filter(([, v]) => v.length > 0);
  return (
    <div>
      <h4 className="text-xs font-semibold uppercase text-slate-400">IoCs (extraídos de la evidencia)</h4>
      {entries.length === 0 ? (
        <p className="mt-1 text-xs">No hay evidencia en los logs proporcionados.</p>
      ) : (
        <div className="mt-1 grid gap-1.5 md:grid-cols-2">
          {entries.map(([kind, values]) => (
            <div key={kind} className="rounded bg-slate-50 px-2 py-1.5 text-xs">
              <span className="font-semibold text-slate-500">{IOC_LABELS[kind] ?? kind}</span>
              <p className="mt-0.5 break-all text-slate-700">
                {values.slice(0, 5).join(" · ")}
                {values.length > 5 ? ` +${values.length - 5}` : ""}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AssetsBlock({ incident }: { incident: Incident }) {
  const a = incident.assets;
  const rows: [string, string[]][] = [
    ["Cuentas afectadas", a.users],
    ["Activos (hosts)", a.hosts],
    ["IPs de origen", a.source_ips],
    ["Destinos", a.destinations],
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

function OverrideForm({
  existing,
  onSubmit,
}: {
  existing: OverrideInfo | null;
  onSubmit: (classification: string, reason: string) => Promise<unknown>;
}) {
  const [classification, setClassification] = useState(existing?.classification ?? "");
  const [reason, setReason] = useState(existing?.reason ?? "");
  const [error, setError] = useState("");
  const [sending, setSending] = useState(false);

  const submit = () => {
    if (!classification) {
      setError("Selecciona una clasificación.");
      return;
    }
    if (!reason.trim()) {
      setError("El motivo del override es obligatorio.");
      return;
    }
    setSending(true);
    onSubmit(classification, reason.trim())
      .catch((e: Error) => setError(e.message))
      .finally(() => setSending(false));
  };

  return (
    <div className="mt-2 rounded border border-purple-200 bg-purple-50 p-3 text-xs">
      <p className="mb-2 text-purple-900">
        El override añade tu clasificación manual y conserva el score automático ({existing ? "actualizado" : "nuevo"}).
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <select
          value={classification}
          onChange={(e) => setClassification(e.target.value)}
          className="rounded border border-slate-300 bg-white px-2 py-1"
        >
          <option value="">— clasificación —</option>
          {OVERRIDE_CLASSIFICATIONS.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <input
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Motivo obligatorio del override…"
          maxLength={2000}
          className="min-w-64 flex-1 rounded border border-slate-300 px-2 py-1"
        />
        <button
          onClick={submit}
          disabled={sending}
          className="rounded bg-purple-700 px-3 py-1 font-medium text-white hover:bg-purple-800 disabled:opacity-50"
        >
          {sending ? "Guardando…" : "Guardar"}
        </button>
      </div>
      {error && <p className="mt-1 text-red-700">{error}</p>}
    </div>
  );
}
