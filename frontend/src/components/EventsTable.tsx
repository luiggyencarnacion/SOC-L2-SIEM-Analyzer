// EventsTable.tsx - Tabla con paginacion 50/100/250, busqueda, filtros, orden y detalle crudo.
import { useEffect, useRef, useState } from "react";
import { getEvents, getRowDetail } from "../api";
import type { EventRow, EventsResponse, RowDetail } from "../types";

export interface TableQuery {
  page: number;
  pageSize: number;
  q: string;
  sort: string | null;
  direction: "asc" | "desc";
  filters: Record<string, string>;
  timeFrom: string | null;
  timeTo: string | null;
}

export const initialQuery: TableQuery = {
  page: 1,
  pageSize: 50,
  q: "",
  sort: null,
  direction: "asc",
  filters: {},
  timeFrom: null,
  timeTo: null,
};

const PAGE_SIZES = [50, 100, 250] as const;

const FILTERABLE_COLUMNS = [
  "timestamp_raw",
  "event_code",
  "host_raw",
  "user_raw",
  "source_ip",
  "destination_raw",
  "result_raw",
  "severity_siem",
  "log_source",
] as const;

const DISPLAY_HEADERS: { key: string; label: string; width?: string }[] = [
  { key: "log_id", label: "Log_ID", width: "w-28" },
  { key: "row_number", label: "Fila", width: "w-14" },
  { key: "timestamp_raw", label: "Timestamp" },
  { key: "host_raw", label: "Host" },
  { key: "user_raw", label: "Usuario" },
  { key: "event_code", label: "Event_ID", width: "w-20" },
  { key: "event_description", label: "Descripción" },
  { key: "source_ip", label: "IP origen", width: "w-32" },
  { key: "destination_raw", label: "Destino", width: "w-36" },
  { key: "result_raw", label: "Result", width: "w-24" },
  { key: "severity_siem", label: "Sev. SIEM", width: "w-24" },
  { key: "log_source", label: "Log origen", width: "w-24" },
];

export function EventsTable({
  sessionId,
  sheet,
  sheets,
  onSheetChange,
  query,
  onQueryChange,
  events,
  setEvents,
  loading,
  setLoading,
  onError,
}: {
  sessionId: string;
  sheet: string;
  sheets: string[];
  onSheetChange: (s: string) => void;
  query: TableQuery;
  onQueryChange: (q: TableQuery) => void;
  events: EventsResponse | null;
  setEvents: (e: EventsResponse) => void;
  loading: boolean;
  setLoading: (v: boolean) => void;
  onError: (msg: string) => void;
}) {
  const [detail, setDetail] = useState<RowDetail | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      try {
        const res = await getEvents({
          sessionId,
          sheet,
          page: query.page,
          pageSize: query.pageSize,
          q: query.q || undefined,
          sort: query.sort ?? undefined,
          direction: query.direction,
          filters: query.filters,
          timeFrom: query.timeFrom ?? undefined,
          timeTo: query.timeTo ?? undefined,
        });
        if (!cancelled) {
          setEvents(res);
          onError("");
        }
      } catch (e) {
        if (!cancelled) onError(e instanceof Error ? e.message : "Error al cargar eventos");
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, [sessionId, sheet, query, setEvents, setLoading, onError]);

  const totalPages = events ? Math.max(1, Math.ceil(events.total / events.page_size)) : 1;

  const setFilter = (col: string, value: string) => {
    const next = { ...query.filters };
    if (value) next[col] = value;
    else delete next[col];
    onQueryChange({ ...query, page: 1, filters: next });
  };

  const hasTimeRange = Boolean(query.timeFrom || query.timeTo);
  const fmtIso = (iso: string | null) => (iso ? iso.replace("T", " ").slice(0, 19) : "");

  const toggleSort = (key: string) => {
    if (query.sort === key) {
      if (query.direction === "asc") onQueryChange({ ...query, direction: "desc" });
      else onQueryChange({ ...query, sort: null, direction: "asc" });
    } else {
      onQueryChange({ ...query, sort: key, direction: "asc", page: 1 });
    }
  };

  const openRow = async (row: EventRow) => {
    try {
      const d = await getRowDetail(sessionId, row.log_id, sheet);
      setDetail(d);
    } catch (e) {
      onError(e instanceof Error ? e.message : "Error al abrir la fila");
    }
  };

  return (
    <div className="space-y-3">
      <div className="bg-white rounded-lg border border-slate-200 p-4 flex flex-wrap gap-3 items-center">
        <select
          value={sheet}
          onChange={(e) => onSheetChange(e.target.value)}
          className="rounded border border-slate-300 px-3 py-1.5 text-sm"
        >
          {sheets.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <input
          ref={searchRef}
          type="search"
          placeholder="Búsqueda global…"
          value={query.q}
          onChange={(e) => onQueryChange({ ...query, page: 1, q: e.target.value })}
          className="rounded border border-slate-300 px-3 py-1.5 text-sm w-72"
        />
        <div className="flex items-center gap-1 text-sm">
          <span className="text-xs text-slate-500">Filas:</span>
          {PAGE_SIZES.map((ps) => (
            <button
              key={ps}
              onClick={() => onQueryChange({ ...query, pageSize: ps, page: 1 })}
              className={`rounded px-2 py-1 text-xs ${
                query.pageSize === ps ? "bg-sky-600 text-white" : "bg-slate-100 hover:bg-slate-200"
              }`}
            >
              {ps}
            </button>
          ))}
        </div>
        {events && (
          <span className="text-sm text-slate-600 ml-auto">
            <strong>{events.total.toLocaleString("es")}</strong> filas
            {loading && <span className="ml-2 text-xs animate-pulse">cargando…</span>}
          </span>
        )}
      </div>

      {hasTimeRange && (
        <div className="flex items-center gap-2 text-xs">
          <span className="rounded bg-sky-100 border border-sky-300 text-sky-900 px-2 py-1">
            Rango temporal: {fmtIso(query.timeFrom)} → {fmtIso(query.timeTo)}
          </span>
          <button
            onClick={() => onQueryChange({ ...query, timeFrom: null, timeTo: null, page: 1 })}
            className="rounded bg-slate-100 hover:bg-slate-200 px-2 py-1 text-slate-600"
          >
            quitar rango ✕
          </button>
        </div>
      )}

      <div className="bg-white rounded-lg border border-slate-200 overflow-x-auto">
        <table className="min-w-full text-xs">
          <thead>
            <tr className="bg-slate-50">
              {DISPLAY_HEADERS.map((h) => (
                <th
                  key={h.key}
                  onClick={() => toggleSort(h.key)}
                  className={`border-b px-2 py-2 text-left font-medium cursor-pointer select-none whitespace-nowrap hover:bg-slate-100 ${h.width ?? ""}`}
                  title="Clic para ordenar"
                >
                  {h.label}
                  {query.sort === h.key ? (query.direction === "asc" ? " ▲" : " ▼") : ""}
                </th>
              ))}
            </tr>
            <tr className="bg-slate-50/60">
              {DISPLAY_HEADERS.map((h) => {
                const filterable = (FILTERABLE_COLUMNS as readonly string[]).includes(h.key);
                return (
                  <th key={h.key + "-f"} className="border-b px-2 py-1">
                    {filterable && (
                      <input
                        value={query.filters[h.key] ?? ""}
                        onChange={(e) => setFilter(h.key, e.target.value)}
                        placeholder="filtrar…"
                        className="w-24 rounded border border-slate-200 px-1.5 py-0.5 text-[11px]"
                      />
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {!events && (
              <tr><td colSpan={DISPLAY_HEADERS.length} className="px-4 py-8 text-center text-slate-500">Cargando…</td></tr>
            )}
            {events && events.rows.length === 0 && (
              <tr><td colSpan={DISPLAY_HEADERS.length} className="px-4 py-8 text-center text-slate-500">
                No hay resultados con los filtros actuales.
              </td></tr>
            )}
            {events?.rows.map((row) => (
              <tr
                key={`${row.log_id}-${row.row_number}`}
                onClick={() => void openRow(row)}
                className="cursor-pointer hover:bg-sky-50 border-b border-slate-100"
                title="Clic para ver la fila cruda"
              >
                <td className="px-2 py-1.5 font-mono">{row.log_id}</td>
                <td className="px-2 py-1.5 text-slate-500">{row.row_number}</td>
                <td className="px-2 py-1.5 whitespace-nowrap">{row.timestamp_raw ?? "—"}</td>
                <td className="px-2 py-1.5 whitespace-nowrap">{row.host_raw ?? "—"}</td>
                <td className="px-2 py-1.5 whitespace-nowrap">{row.user_raw ?? "—"}</td>
                <td className="px-2 py-1.5">{row.event_code ?? "—"}</td>
                <td className="px-2 py-1.5 max-w-96 truncate" title={row.event_description ?? ""}>
                  {row.event_description ?? "—"}
                </td>
                <td className="px-2 py-1.5">{row.source_ip ?? "—"}</td>
                <td className="px-2 py-1.5 max-w-36 truncate" title={row.destination_raw ?? ""}>{row.destination_raw ?? "—"}</td>
                <td className="px-2 py-1.5">
                  <ResultBadge norm={row.result_norm} raw={row.result_raw} />
                </td>
                <td className="px-2 py-1.5">{row.severity_siem ?? "—"}</td>
                <td className="px-2 py-1.5">{row.log_source ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {events && events.total > 0 && (
        <div className="flex items-center justify-between text-sm">
          <span className="text-slate-500">
            Página {events.page} de {totalPages}
          </span>
          <div className="flex gap-2">
            <button
              disabled={events.page <= 1}
              onClick={() => onQueryChange({ ...query, page: events.page - 1 })}
              className="rounded border px-3 py-1 disabled:opacity-40 hover:bg-slate-100"
            >
              ◄ Anterior
            </button>
            <button
              disabled={events.page >= totalPages}
              onClick={() => onQueryChange({ ...query, page: events.page + 1 })}
              className="rounded border px-3 py-1 disabled:opacity-40 hover:bg-slate-100"
            >
              Siguiente ►
            </button>
          </div>
        </div>
      )}

      {detail && <RowDetailModal detail={detail} onClose={() => setDetail(null)} />}
    </div>
  );
}

function ResultBadge({ norm, raw }: { norm?: string | null; raw?: string | null }) {
  const color =
    norm === "success"
      ? "bg-emerald-100 text-emerald-800"
      : norm === "failure"
        ? "bg-amber-100 text-amber-800"
        : norm === "denied"
          ? "bg-orange-100 text-orange-800"
          : norm === "error"
            ? "bg-red-100 text-red-800"
            : "bg-slate-100 text-slate-700";
  return <span className={`rounded px-1.5 py-0.5 text-[11px] ${color}`}>{raw ?? "—"}</span>;
}

function RowDetailModal({ detail, onClose }: { detail: RowDetail; onClose: () => void }) {
  const fields = Object.entries(detail).filter(
    ([k]) => !["raw", "columns", "extracted", "quality_flags"].includes(k) && detail[k] !== undefined,
  );
  const rawRow = (detail.raw?.fields ?? []) as unknown[];
  const columns = detail.columns ?? [];
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div
        className="bg-white rounded-lg max-w-4xl w-full max-h-[85vh] overflow-y-auto p-6 space-y-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h3 className="text-base font-semibold font-mono">{String(detail.log_id)}</h3>
          <button onClick={onClose} className="rounded bg-slate-100 hover:bg-slate-200 px-3 py-1 text-sm">
            Cerrar
          </button>
        </div>
        {detail.quality_flags.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {detail.quality_flags.map((f) => (
              <span key={f} className="rounded bg-amber-100 text-amber-800 px-2 py-0.5 text-xs">{f}</span>
            ))}
          </div>
        )}
        <section>
          <h4 className="text-sm font-semibold mb-2">Campos normalizados</h4>
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-1 text-sm">
            {fields.map(([k, v]) => (
              <div key={k} className="border-b border-slate-100 py-1 flex gap-2">
                <dt className="text-slate-500 min-w-40">{k}</dt>
                <dd className="break-all">{v === null ? <span className="text-slate-400">null</span> : String(v)}</dd>
              </div>
            ))}
          </dl>
        </section>
        <section>
          <h4 className="text-sm font-semibold mb-2">Evidencia · fila cruda</h4>
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-1 text-sm">
            {columns.map((col, i) => (
              <div key={`${col}-${i}`} className="border-b border-slate-100 py-1 flex gap-2">
                <dt className="text-slate-500 min-w-40">{col}</dt>
                <dd className="break-all font-mono text-xs">
                  {rawRow[i] === null || rawRow[i] === undefined ? (
                    <span className="text-slate-400">vacío</span>
                  ) : (
                    String(rawRow[i])
                  )}
                </dd>
              </div>
            ))}
          </dl>
        </section>
      </div>
    </div>
  );
}
