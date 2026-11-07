// DashboardPanel.tsx - Dashboard interactivo (fase D).
// KPIs, graficos que filtran (drill-down), timeline, heatmap hora x dia,
// comparacion severidad SIEM vs calculada y MITRE. Todos los datos vienen del
// endpoint determinista /stats: nada se inventa en el cliente.
import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { Bar, BarChart, CartesianGrid, Cell, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { getStats } from "../api";
import type { DashboardStats, StatEntry } from "../types";

// Orden canonico del PLAN (7.1); valores fuera de la lista van despues.
const SEVERITY_ORDER = ["Crítico", "Alto", "Medio", "Bajo"];
const SEV_COLORS: Record<string, string> = {
  "Crítico": "#dc2626",
  Alto: "#ea580c",
  Medio: "#d97706",
  Bajo: "#64748b",
};
const FALLBACK_COLOR = "#0284c7";

interface Props {
  sessionId: string;
  sheet: string;
  onError: (msg: string) => void;
  onDrillSeverity: (severity: string) => void;
  onDrillFindingsQuery: (q: string) => void;
  onDrillEventFilter: (field: string, value: string) => void;
  onDrillTimeRange: (from: string, to: string) => void;
  onGoIncidents: () => void;
  onGoCoverage: () => void;
  onGoQuality: () => void;
}

function orderBySeverity(entries: StatEntry[]): StatEntry[] {
  const known = SEVERITY_ORDER.filter((s) => entries.some((e) => e.value === s)).map(
    (s) => entries.find((e) => e.value === s)!,
  );
  const extra = entries.filter((e) => !SEVERITY_ORDER.includes(e.value));
  return [...known, ...extra];
}

function rowOf(d: unknown): Record<string, unknown> | null {
  if (!d || typeof d !== "object") return null;
  const obj = d as Record<string, unknown>;
  const payload = obj.payload && typeof obj.payload === "object" ? obj.payload : obj;
  return payload as Record<string, unknown>;
}

function toLocalIso(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(
    d.getMinutes(),
  )}:${pad(d.getSeconds())}`;
}

/** Fin del rango de un bucket: bucket + 1h (o 1 dia) menos 1 segundo. */
function bucketEnd(bucket: string, granularity: "hour" | "day"): string {
  const start = new Date(bucket);
  const ms = granularity === "hour" ? 3_600_000 : 86_400_000;
  return toLocalIso(new Date(start.getTime() + ms - 1000));
}

function fmtBucket(bucket: string, granularity: "hour" | "day"): string {
  return granularity === "hour" ? bucket.slice(0, 16).replace("T", " ") : bucket;
}

function shortIso(iso: string | null): string {
  return iso ? iso.replace("T", " ").slice(0, 16) : "—";
}

export function DashboardPanel({
  sessionId,
  sheet,
  onError,
  onDrillSeverity,
  onDrillFindingsQuery,
  onDrillEventFilter,
  onDrillTimeRange,
  onGoIncidents,
  onGoCoverage,
  onGoQuality,
}: Props) {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    getStats(sessionId, sheet)
      .then((res) => {
        if (!cancelled) {
          setStats(res);
          onError("");
        }
      })
      .catch((e: Error) => {
        if (!cancelled) onError(`No se pudo cargar el dashboard: ${e.message}`);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [sessionId, sheet, onError]);

  if (loading) return <p className="text-sm text-slate-500">Cargando dashboard…</p>;
  if (!stats) return null;

  const k = stats.kpis;
  const qualityTotal = Object.values(k.quality_alerts).reduce((a, b) => a + b, 0);
  const gran = stats.events_timeline.granularity;
  const timelineData = stats.events_timeline.buckets.map((b) => ({ bucket: b.bucket, count: b.count }));
  const sevData = orderBySeverity(Object.entries(k.findings_by_severity).map(([value, count]) => ({ value, count })));
  const bandData = orderBySeverity(Object.entries(k.incidents_by_band).map(([value, count]) => ({ value, count })));
  const sc = stats.siem_vs_calculated;
  const scData = sc.categories.map((sev, i) => ({ sev, siem: sc.siem_events[i], calc: sc.calculated_findings[i] }));
  const heatMax = Math.max(1, ...stats.heatmap.cells.map((c) => c.count));

  return (
    <div className="space-y-4">
      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Kpi label="Eventos" value={k.total_events.toLocaleString("es")} sub={`${k.events_with_timestamp.toLocaleString("es")} con timestamp`} />
        <Kpi label="Hallazgos" value={k.total_findings.toLocaleString("es")} sub={sevText(k.findings_by_severity)} />
        <Kpi label="Incidentes" value={k.total_incidents.toLocaleString("es")} sub={sevText(k.incidents_by_band)} onClick={onGoIncidents} />
        <Kpi
          label="Activos y cuentas"
          value={`${k.affected_users} / ${k.affected_hosts} / ${k.affected_source_ips}`}
          sub="usuarios / hosts / IPs origen"
        />
        <Kpi
          label="Reglas"
          value={`${k.rules_executed} / ${k.rules_total}`}
          sub={`${k.rules_skipped} omitidas · ${k.rules_error} con error`}
          onClick={onGoCoverage}
        />
        <Kpi
          label="Alertas de calidad"
          value={qualityTotal.toLocaleString("es")}
          sub={`ts inválidos ${k.quality_alerts.invalid_timestamps} · duplicados ${k.quality_alerts.duplicate_log_ids}`}
          onClick={onGoQuality}
        />
        <Kpi label="Overrides manuales" value={k.manual_overrides.toLocaleString("es")} sub="clasificaciones del analista" />
        <Kpi label="Rango temporal" value={`${shortIso(k.time_range.start)} → ${shortIso(k.time_range.end)}`} sub="según timestamps de los logs" small />
      </div>

      {k.total_events === 0 && (
        <p className="rounded border border-slate-200 bg-white px-4 py-6 text-sm text-slate-500">
          No hay eventos en este análisis; el dashboard se llenará al cargar logs con datos.
        </p>
      )}

      {/* Graficos: fila 1 */}
      <div className="grid gap-4 md:grid-cols-2">
        <ChartCard title="Hallazgos por criticidad" subtitle="Clic en una barra → hallazgos filtrados por esa severidad">
          {sevData.length === 0 ? (
            <EmptyChart text="No hay hallazgos para este análisis." />
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sevData} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="value" tick={{ fontSize: 11 }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11 }} />
                <Tooltip />
                <Bar dataKey="count" cursor="pointer" onClick={(d) => {
                  const row = rowOf(d);
                  if (row?.value) onDrillSeverity(String(row.value));
                }}>
                  {sevData.map((e) => (
                    <Cell key={e.value} fill={SEV_COLORS[e.value] ?? FALLBACK_COLOR} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        <ChartCard title="Incidentes por banda de score" subtitle="Clic → ver incidentes. Banda calculada por el motor (PLAN 7)">
          {bandData.length === 0 ? (
            <EmptyChart text="No hay incidentes para este análisis." />
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={bandData} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="value" tick={{ fontSize: 11 }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11 }} />
                <Tooltip />
                <Bar dataKey="count" fill="#4f46e5" cursor="pointer" onClick={() => onGoIncidents()} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>
      </div>

      {/* Timeline (ancho completo) */}
      <ChartCard
        title="Timeline de eventos"
        subtitle={`Buckets por ${gran === "hour" ? "hora" : "día"} · clic en una barra → tabla filtrada a ese rango`}
      >
        {timelineData.length === 0 ? (
          <EmptyChart text="No hay eventos con timestamp válido." />
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={timelineData} margin={{ top: 8, right: 8, left: -8, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis
                dataKey="bucket"
                tickFormatter={(v: string) => fmtBucket(v, gran)}
                tick={{ fontSize: 10 }}
                minTickGap={24}
              />
              <YAxis allowDecimals={false} tick={{ fontSize: 11 }} />
              <Tooltip labelFormatter={(v) => fmtBucket(String(v), gran)} />
              <Bar
                dataKey="count"
                fill={FALLBACK_COLOR}
                cursor="pointer"
                onClick={(d) => {
                  const row = rowOf(d);
                  if (row?.bucket) onDrillTimeRange(String(row.bucket), bucketEnd(String(row.bucket), gran));
                }}
              />
            </BarChart>
          </ResponsiveContainer>
        )}
      </ChartCard>

      {/* SIEM vs calculada */}
      <ChartCard
        title="Severidad SIEM vs severidad calculada"
        subtitle="Eventos por severidad declarada del SIEM frente a hallazgos por severidad del motor. Clic: SIEM → tabla de eventos; calculada → hallazgos"
      >
        {scData.length === 0 ? (
          <EmptyChart text="No hay severidades para comparar." />
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={scData} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="sev" tick={{ fontSize: 11 }} />
              <YAxis allowDecimals={false} tick={{ fontSize: 11 }} />
              <Tooltip />
              <Legend />
              <Bar
                dataKey="siem"
                name="Eventos (severidad SIEM)"
                fill="#0ea5e9"
                cursor="pointer"
                onClick={(d) => {
                  const row = rowOf(d);
                  if (row?.sev) onDrillEventFilter("severity_siem", String(row.sev));
                }}
              />
              <Bar
                dataKey="calc"
                name="Hallazgos (calculada)"
                fill="#6366f1"
                cursor="pointer"
                onClick={(d) => {
                  const row = rowOf(d);
                  if (row?.sev) onDrillSeverity(String(row.sev));
                }}
              />
            </BarChart>
          </ResponsiveContainer>
        )}
      </ChartCard>

      {/* Tops */}
      <div className="grid gap-4 md:grid-cols-3">
        <TopChart
          title="Top IPs de origen"
          entries={stats.top.source_ips}
          onClick={(v) => onDrillEventFilter("source_ip", v)}
        />
        <TopChart title="Top usuarios" entries={stats.top.users} onClick={(v) => onDrillEventFilter("user_raw", v)} />
        <TopChart title="Top hosts" entries={stats.top.hosts} onClick={(v) => onDrillEventFilter("host_raw", v)} />
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <TopChart
          title="Eventos por Event_ID"
          entries={stats.top.event_codes}
          onClick={(v) => onDrillEventFilter("event_code", v)}
        />
        <TopChart
          title="Eventos por origen de log"
          entries={stats.top.log_sources}
          onClick={(v) => onDrillEventFilter("log_source", v)}
        />
        <TopChart
          title="Tácticas y técnicas MITRE"
          entries={stats.mitre.slice(0, 10)}
          onClick={(v) => onDrillFindingsQuery(v)}
        />
      </div>

      {/* Heatmap hora x dia */}
      <ChartCard
        title="Heatmap hora × día"
        subtitle="Volumen de eventos por franja; clic en una celda → tabla filtrada a esa hora"
      >
        {stats.heatmap.cells.length === 0 ? (
          <EmptyChart text="No hay eventos con timestamp válido." />
        ) : (
          <div className="overflow-x-auto">
            <HeatmapGrid days={stats.heatmap.days} cells={stats.heatmap.cells} max={heatMax} onPick={onDrillTimeRange} />
          </div>
        )}
      </ChartCard>
    </div>
  );
}

function sevText(map: Record<string, number>): string {
  const entries = Object.entries(map);
  if (entries.length === 0) return "sin datos";
  return orderBySeverity(entries.map(([value, count]) => ({ value, count })))
    .map((e) => `${e.value} ${e.count}`)
    .join(" · ");
}

function Kpi({
  label,
  value,
  sub,
  onClick,
  small,
}: {
  label: string;
  value: string;
  sub?: string;
  onClick?: () => void;
  small?: boolean;
}) {
  const Tag = onClick ? "button" : "div";
  return (
    <Tag
      onClick={onClick}
      className={`rounded border border-slate-200 bg-white p-3 text-left ${onClick ? "hover:border-sky-400 hover:bg-sky-50 cursor-pointer" : ""}`}
    >
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`font-semibold text-slate-800 ${small ? "text-sm" : "text-xl"}`}>{value}</p>
      {sub && <p className="mt-0.5 text-[11px] text-slate-500">{sub}</p>}
    </Tag>
  );
}

function ChartCard({
  title,
  subtitle,
  chartHeight = 224,
  children,
}: {
  title: string;
  subtitle?: string;
  /** Alto del area del grafico en px; los tops usan mas alto segun entradas. */
  chartHeight?: number;
  children: ReactNode;
}) {
  return (
    <section className="rounded border border-slate-200 bg-white p-4">
      <h3 className="text-sm font-semibold text-slate-800">{title}</h3>
      {subtitle && <p className="mt-0.5 text-[11px] text-slate-500">{subtitle}</p>}
      <div className="mt-2" style={{ height: chartHeight }}>
        {children}
      </div>
    </section>
  );
}

function EmptyChart({ text }: { text: string }) {
  return <p className="flex h-full items-center justify-center text-sm text-slate-400">{text}</p>;
}

/** Etiqueta del eje acortada si es muy larga; el valor completo va en el tooltip. */
function shortTick(value: string): string {
  return value.length <= 20 ? value : `${value.slice(0, 10)}…${value.slice(-8)}`;
}

function TopChart({ title, entries, onClick }: { title: string; entries: StatEntry[]; onClick: (v: string) => void }) {
  // Alto proporcional al numero de entradas: con el alto fijo Recharts oculta
  // etiquetas del eje de categoria (interval por defecto) y algunos valores no
  // se leian a la izquierda. Con interval={0} + alto suficiente se ven todas.
  const chartHeight = Math.max(180, entries.length * 32 + 40);
  return (
    <ChartCard title={title} subtitle="Clic en una barra → tabla filtrada" chartHeight={chartHeight}>
      {entries.length === 0 ? (
        <EmptyChart text="Sin datos." />
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={entries} layout="vertical" margin={{ top: 4, right: 16, left: 8, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" horizontal={false} />
            <XAxis type="number" allowDecimals={false} tick={{ fontSize: 10 }} />
            <YAxis
              type="category"
              dataKey="value"
              width={130}
              interval={0}
              tick={{ fontSize: 10 }}
              tickFormatter={(v: string) => shortTick(v)}
            />
            <Tooltip />
            <Bar dataKey="count" fill={FALLBACK_COLOR} cursor="pointer" onClick={(d) => {
              const row = rowOf(d);
              if (row?.value) onClick(String(row.value));
            }} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </ChartCard>
  );
}

function HeatmapGrid({
  days,
  cells,
  max,
  onPick,
}: {
  days: string[];
  cells: { day: string; hour: number; count: number }[];
  max: number;
  onPick: (from: string, to: string) => void;
}) {
  const byKey = new Map(cells.map((c) => [`${c.day}|${c.hour}`, c.count]));
  return (
    <table className="border-separate border-spacing-0 text-[10px]">
      <thead>
        <tr>
          <th className="px-1 text-slate-400">día \ h</th>
          {Array.from({ length: 24 }, (_, h) => (
            <th key={h} className="px-0.5 font-medium text-slate-500">
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {days.map((day) => (
          <tr key={day}>
            <th className="px-1 text-left font-medium text-slate-500">{day.slice(5)}</th>
            {Array.from({ length: 24 }, (_, h) => {
              const count = byKey.get(`${day}|${h}`) ?? 0;
              const alpha = count === 0 ? 0 : 0.15 + 0.85 * (count / max);
              return (
                <td key={h} className="p-0">
                  {count === 0 ? (
                    <div className="h-5 w-5 rounded-sm bg-slate-100" />
                  ) : (
                    <button
                      onClick={() => onPick(`${day}T${String(h).padStart(2, "0")}:00:00`, bucketEnd(`${day}T${String(h).padStart(2, "0")}:00:00`, "hour"))}
                      className="h-5 w-5 rounded-sm text-center font-semibold text-white hover:ring-2 hover:ring-sky-500"
                      style={{ backgroundColor: `rgba(2, 132, 199, ${alpha.toFixed(2)})` }}
                      title={`${day} ${String(h).padStart(2, "0")}:00 — ${count} evento(s). Clic para filtrar.`}
                      aria-label={`${day} hora ${h}: ${count} eventos`}
                    >
                      {count}
                    </button>
                  )}
                </td>
              );
            })}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
