// NarrativePanel.tsx - Fase E: redaccion de secciones del informe.
// Con AI_PROVIDER=none todo sale de plantillas deterministas; con IA, cada
// parrafo pasa por el validador anti-alucinacion del backend y los rechazados
// caen a plantilla. Los Log_ID citados son clickeables (abren la fila cruda).
import { useEffect, useState } from "react";
import { generateNarrative, getAiSettings, getNarrative, testAiConnection } from "../api";
import type { AiSettings, AiTestResult, NarrativeResponse } from "../types";

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

export function NarrativePanel({ sessionId, sheet, onError, onOpenEvidence }: Props) {
  const [settings, setSettings] = useState<AiSettings | null>(null);
  const [narrative, setNarrative] = useState<NarrativeResponse | null>(null);
  const [generating, setGenerating] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<AiTestResult | null>(null);
  const [expanded, setExpanded] = useState<string | null>("resumen_ejecutivo");

  useEffect(() => {
    let cancelled = false;
    getAiSettings()
      .then((s) => {
        if (!cancelled) setSettings(s);
      })
      .catch((e: Error) => {
        if (!cancelled) onError(`No se pudo cargar la configuración de IA: ${e.message}`);
      });
    getNarrative(sessionId, sheet)
      .then((n) => {
        if (!cancelled) setNarrative(n);
      })
      .catch(() => undefined); // sin redaccion previa: panel vacio hasta generar
    return () => {
      cancelled = true;
    };
  }, [sessionId, sheet, onError]);

  const onGenerate = () => {
    setGenerating(true);
    setTestResult(null);
    generateNarrative(sessionId, sheet)
      .then((n) => {
        setNarrative(n);
        setExpanded("resumen_ejecutivo");
        onError("");
      })
      .catch((e: Error) => onError(`No se pudo generar la redacción: ${e.message}`))
      .finally(() => setGenerating(false));
  };

  const onTest = () => {
    setTesting(true);
    testAiConnection()
      .then((r) => {
        setTestResult(r);
        onError("");
      })
      .catch((e: Error) => setTestResult({ ok: false, provider: "", effective_provider: "", mode: "plantillas", detail: e.message }))
      .finally(() => setTesting(false));
  };

  const rejected = narrative?.ai_state?.rejected ?? [];

  return (
    <div className="space-y-4">
      {/* --- Ajustes IA (PLAN 10): proveedor, modelo, estado de clave, prueba --- */}
      <section className="rounded border border-slate-200 bg-white">
        <header className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-3">
          <h2 className="text-sm font-semibold text-slate-800">Ajustes de IA</h2>
          {settings && (
            <span
              className={`rounded-full border px-2 py-0.5 text-xs ${
                settings.mode === "ia"
                  ? "border-emerald-300 bg-emerald-100 text-emerald-800"
                  : "border-slate-300 bg-slate-100 text-slate-700"
              }`}
            >
              {settings.mode === "ia"
                ? `IA activa (${settings.effective_provider})`
                : "Plantillas deterministas"}
            </span>
          )}
          <button
            onClick={onTest}
            disabled={testing}
            className="ml-auto rounded bg-sky-600 px-3 py-1.5 text-xs text-white hover:bg-sky-700 disabled:opacity-50"
          >
            {testing ? "Probando…" : "Probar conexión"}
          </button>
        </header>
        {settings && (
          <div className="grid grid-cols-2 gap-x-6 gap-y-1 px-4 py-3 text-xs text-slate-600 sm:grid-cols-4">
            <span>Proveedor: <strong className="text-slate-800">{settings.provider}</strong></span>
            <span>Modelo: <strong className="text-slate-800">{settings.model || "—"}</strong></span>
            <span>
              Clave:{" "}
              <strong className={settings.key_configured ? "text-emerald-700" : "text-slate-500"}>
                {settings.key_configured ? "configurada" : "no configurada"}
              </strong>{" "}
              <span className="text-slate-400">(nunca se muestra)</span>
            </span>
            <span>Temperatura: <strong className="text-slate-800">{settings.temperature}</strong></span>
            {settings.base_url && <span>Base URL: <code>{settings.base_url}</code></span>}
            <span className="col-span-2 sm:col-span-4 text-slate-400">
              La clave vive solo en <code>.env</code> del backend. La IA no detecta: solo redacta a
              partir de hallazgos estructurados y su salida se valida antes de mostrarse.
            </span>
          </div>
        )}
        {testResult && (
          <div
            className={`px-4 py-2 text-xs border-t ${
              testResult.ok
                ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                : "border-red-200 bg-red-50 text-red-800"
            }`}
            role="status"
          >
            Prueba de conexión: {testResult.detail}
          </div>
        )}
      </section>

      {/* --- Generacion --- */}
      <section className="rounded border border-slate-200 bg-white">
        <header className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-3">
          <h2 className="text-sm font-semibold text-slate-800">Redacción del informe</h2>
          {narrative && (
            <span className="text-xs text-slate-500">
              {narrative.mode === "ia" ? "IA validada" : "Plantillas deterministas"} ·{" "}
              {narrative.total_sections} sección(es) · {narrative.total_paragraphs} párrafo(s)
            </span>
          )}
          <button
            onClick={onGenerate}
            disabled={generating}
            className="ml-auto rounded bg-emerald-600 px-3 py-1.5 text-xs text-white hover:bg-emerald-700 disabled:opacity-50"
          >
            {generating ? "Generando…" : narrative ? "Regenerar redacción" : "Generar redacción"}
          </button>
        </header>

        {narrative && narrative.ai_state && narrative.mode === "ia" && (
          <div className="border-b border-slate-200 bg-slate-50 px-4 py-2 text-xs text-slate-600">
            Validación anti-alucinación: {narrative.ai_state.accepted_paragraphs} párrafo(s) de IA
            aceptado(s), {rejected.length} descartado(s)
            {narrative.ai_state.masking ? " · enmascaramiento reversible aplicado" : ""}.
            {rejected.length > 0 && (
              <ul className="mt-1 list-disc pl-5 text-red-700">
                {rejected.slice(0, 10).map((r, i) => (
                  <li key={i}>
                    <code className="text-[11px]">{r.section}</code>: {r.reason}
                  </li>
                ))}
              </ul>
            )}
            {rejected.length > 0 && (
              <p className="mt-1 text-slate-500">Los párrafos descartados se sustituyen por la plantilla determinista.</p>
            )}
          </div>
        )}

        {!narrative && (
          <p className="px-4 py-6 text-sm text-slate-500">
            Sin redacción todavía. Pulsa «Generar redacción»: el texto se construye a partir de los
            hallazgos e incidentes del motor determinista, con evidencia por Log_ID.
          </p>
        )}

        {narrative && (
          <div className="divide-y divide-slate-100">
            {narrative.sections.map((s) => {
              const open = expanded === s.section_id;
              return (
                <div key={s.section_id}>
                  <button
                    onClick={() => setExpanded(open ? null : s.section_id)}
                    className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-slate-50"
                  >
                    <span className="text-xs text-slate-400">{open ? "▾" : "▸"}</span>
                    <span className="text-sm font-medium text-slate-800">{s.title}</span>
                    <span className="ml-auto text-xs text-slate-400">{s.paragraphs.length} párrafo(s)</span>
                  </button>
                  {open && (
                    <div className="space-y-3 px-4 pb-4 pt-1">
                      {s.paragraphs.map((p, i) => (
                        <div key={i} className="rounded border border-slate-200 bg-slate-50 px-3 py-2">
                          <div className="mb-1 flex items-center gap-2 text-[11px]">
                            <span className={`rounded border px-1.5 py-0.5 ${LABEL_STYLES[p.label] ?? LABEL_STYLES["Hipótesis"]}`}>
                              {p.label}
                            </span>
                            <span
                              className={`rounded border px-1.5 py-0.5 ${
                                p.source === "ia_validada"
                                  ? "border-sky-300 bg-sky-100 text-sky-800"
                                  : "border-slate-300 bg-white text-slate-500"
                              }`}
                            >
                              {p.source === "ia_validada" ? "IA validada" : "plantilla"}
                            </span>
                          </div>
                          <p className="text-sm leading-relaxed text-slate-700">{p.text}</p>
                          {p.citations.length > 0 && (
                            <div className="mt-1.5 flex flex-wrap items-center gap-1 text-[11px] text-slate-500">
                              Evidencia:
                              {p.citations.map((c) => (
                                <button
                                  key={c}
                                  onClick={() => onOpenEvidence(c)}
                                  className="rounded border border-sky-300 bg-sky-50 px-1.5 py-0.5 font-mono text-sky-700 hover:bg-sky-100"
                                  title="Abrir la fila cruda en la tabla de eventos"
                                >
                                  {c}
                                </button>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
