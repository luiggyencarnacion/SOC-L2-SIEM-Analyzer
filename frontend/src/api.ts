// api.ts - Cliente tipado de la API (rutas relativas al proxy /api de Vite).
import type {
  AnalyzeResponse,
  DataQualityReport,
  EventsResponse,
  MappingEntry,
  RowDetail,
  UploadResponse,
} from "./types";

class ApiError extends Error {}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) {
    let detail = `Error HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
    } catch {
      /* sin cuerpo json */
    }
    throw new ApiError(detail);
  }
  return (await res.json()) as T;
}

export async function uploadFile(file: File): Promise<UploadResponse> {
  const form = new FormData();
  form.append("file", file);
  return request<UploadResponse>("/api/upload", { method: "POST", body: form });
}

export interface AnalyzePayload {
  sessionId: string;
  sheet: string;
  headerRow: number;
  mapping: MappingEntry[];
}

export async function analyzeSheet(p: AnalyzePayload): Promise<AnalyzeResponse> {
  return request<AnalyzeResponse>(`/api/sessions/${p.sessionId}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sheet: p.sheet, header_row: p.headerRow, mapping: p.mapping }),
  });
}

export interface EventsParams {
  sessionId: string;
  sheet: string;
  page: number;
  pageSize: number;
  q?: string;
  sort?: string;
  direction?: "asc" | "desc";
  filters?: Record<string, string>;
}

export async function getEvents(p: EventsParams): Promise<EventsResponse> {
  const sp = new URLSearchParams({
    sheet: p.sheet,
    page: String(p.page),
    page_size: String(p.pageSize),
  });
  if (p.q) sp.set("q", p.q);
  if (p.sort) sp.set("sort", p.sort);
  if (p.sort) sp.set("direction", p.direction ?? "asc");
  if (p.filters && Object.keys(p.filters).length > 0) {
    sp.set("filters", JSON.stringify(p.filters));
  }
  return request<EventsResponse>(`/api/sessions/${p.sessionId}/events?${sp.toString()}`);
}

export async function getRowDetail(sessionId: string, logId: string, sheet: string): Promise<RowDetail> {
  return request<RowDetail>(
    `/api/sessions/${sessionId}/events/${encodeURIComponent(logId)}?sheet=${encodeURIComponent(sheet)}`,
  );
}

export async function deleteSession(sessionId: string): Promise<void> {
  await request(`/api/sessions/${sessionId}`, { method: "DELETE" });
}

export async function getQuality(sessionId: string, sheet: string): Promise<DataQualityReport> {
  return request<DataQualityReport>(
    `/api/sessions/${sessionId}/quality?sheet=${encodeURIComponent(sheet)}`,
  );
}
