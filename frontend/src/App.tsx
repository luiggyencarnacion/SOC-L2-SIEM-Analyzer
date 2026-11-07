// App.tsx - Flujo fase A: subir -> revisar hoja/mapeo -> tabla de eventos.
import { useCallback, useState } from "react";
import type { AnalyzeResponse, UploadResponse } from "./types";
import type { DataQualityReport } from "./types";
import type { EventsResponse } from "./types";
import type { TableQuery } from "./components/EventsTable";
import { initialQuery } from "./components/EventsTable";
import { UploadZone } from "./components/UploadZone";
import { MappingEditor } from "./components/MappingEditor";
import { EventsTable } from "./components/EventsTable";
import { QualityPanel } from "./components/QualityPanel";
import { AliasesPanel } from "./components/AliasesPanel";

type Step = "upload" | "mapping" | "table";

function fmtSize(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

export default function App() {
  const [step, setStep] = useState<Step>("upload");
  const [session, setSession] = useState<UploadResponse | null>(null);
  const [sheet, setSheet] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [quality, setQuality] = useState<DataQualityReport | null>(null);
  const [aliases, setAliases] = useState<AnalyzeResponse["aliases"] | null>(null);
  const [query, setQuery] = useState<TableQuery>(initialQuery);
  const [events, setEvents] = useState<EventsResponse | null>(null);
  const [loading, setLoading] = useState(false);

  const onUploaded = useCallback((res: UploadResponse) => {
    setSession(res);
    setSheet(res.sheets[0]?.name ?? "");
    setQuality(null);
    setAliases(null);
    setQuery(initialQuery);
    setEvents(null);
    setError(null);
    setStep("mapping");
  }, []);

  const onAnalyzed = useCallback(
    (totalRows: number, q: DataQualityReport, al: AnalyzeResponse["aliases"]) => {
      setQuality(q);
      setAliases(al);
      setStep("table");
      setError(null);
      void totalRows;
    },
    [],
  );

  const reset = useCallback(() => {
    if (session) void fetch(`/api/sessions/${session.session_id}`, { method: "DELETE" }).catch(() => undefined);
    setSession(null);
    setSheet("");
    setQuality(null);
    setAliases(null);
    setEvents(null);
    setQuery(initialQuery);
    setError(null);
    setStep("upload");
  }, [session]);

  const showError = (msg: string) => setError(msg);

  return (
    <div className="min-h-screen bg-slate-100 text-slate-800">
      <header className="bg-slate-900 text-white px-6 py-4 flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">SOC L2 SIEM Analyzer</h1>
          <p className="text-xs text-slate-400">Fase A · captación, normalización y tabla de eventos</p>
        </div>
        <nav className="flex items-center gap-3 text-sm">
          <StepDot active={step !== "upload"} label="1 · Archivo" />
          <StepDot active={step === "mapping" || step === "table"} label="2 · Hoja y mapeo" />
          <StepDot active={step === "table"} label="3 · Tabla" />
          {session && (
            <button
              onClick={reset}
              className="ml-4 rounded bg-slate-700 hover:bg-slate-600 px-3 py-1.5 text-xs"
            >
              Nueva sesión
            </button>
          )}
        </nav>
      </header>

      <main className="max-w-7xl mx-auto p-6 space-y-4">
        {error && (
          <div className="rounded bg-red-100 border border-red-300 text-red-800 px-4 py-2 text-sm" role="alert">
            {error}
          </div>
        )}

        {session && (
          <div className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm text-slate-600 bg-white rounded border border-slate-200 px-4 py-3">
            <span className="font-medium text-slate-800">{session.file_name}</span>
            <span>{fmtSize(session.size_bytes)}</span>
            <span>Sesión <code className="text-xs">{session.session_id.slice(0, 8)}</code></span>
            {sheet && <span>Hoja activa: <strong>{sheet}</strong></span>}
          </div>
        )}

        {step === "upload" && <UploadZone onUploaded={onUploaded} onError={showError} />}

        {step === "mapping" && session && (
          <MappingEditor
            session={session}
            sheet={sheet}
            onSheetChange={setSheet}
            onAnalyzed={onAnalyzed}
            onError={showError}
          />
        )}

        {step === "table" && session && (
          <div className="space-y-4">
            <EventsTable
              sessionId={session.session_id}
              sheet={sheet}
              sheets={session.sheets.map((s) => s.name)}
              onSheetChange={setSheet}
              query={query}
              onQueryChange={setQuery}
              events={events}
              setEvents={setEvents}
              loading={loading}
              setLoading={setLoading}
              onError={showError}
            />
            {quality && <QualityPanel quality={quality} />}
            {aliases && <AliasesPanel aliases={aliases} />}
          </div>
        )}
      </main>

      <footer className="text-center text-xs text-slate-500 py-6">
        Análisis determinista · sin IA en la detección · evidencia por Log_ID
      </footer>
    </div>
  );
}

function StepDot({ active, label }: { active: boolean; label: string }) {
  return (
    <span className={active ? "text-emerald-400" : "text-slate-500"}>{label}</span>
  );
}
