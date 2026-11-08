// api.ts - Cliente tipado de la API (rutas relativas al proxy /api de Vite).
import type {
  AnalyzeResponse,
  AiSettings,
  AiSettingsUpdate,
  AiTestResult,
  CorrelationResponse,
  CoverageResponse,
  DashboardStats,
  DataQualityReport,
  EventsResponse,
  FindingsResponse,
  MappingEntry,
  NarrativeResponse,
  OverrideInfo,
  ReportResponse,
  ReportSection,
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
  timeFrom?: string;
  timeTo?: string;
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
  if (p.timeFrom) sp.set("time_from", p.timeFrom);
  if (p.timeTo) sp.set("time_to", p.timeTo);
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

// ---------- Fase B: deteccion ----------

export async function getFindings(
  sessionId: string,
  sheet: string,
  severity?: string,
  rule?: string,
  q?: string,
): Promise<FindingsResponse> {
  const sp = new URLSearchParams({ sheet });
  if (severity) sp.set("severity", severity);
  if (rule) sp.set("rule", rule);
  if (q) sp.set("q", q);
  return request<FindingsResponse>(`/api/sessions/${sessionId}/findings?${sp.toString()}`);
}

export async function getCoverage(sessionId: string, sheet: string): Promise<CoverageResponse> {
  return request<CoverageResponse>(
    `/api/sessions/${sessionId}/coverage?sheet=${encodeURIComponent(sheet)}`,
  );
}

// ---------- Fase C: correlacion y override ----------

export async function getIncidents(sessionId: string, sheet: string): Promise<CorrelationResponse> {
  return request<CorrelationResponse>(
    `/api/sessions/${sessionId}/incidents?sheet=${encodeURIComponent(sheet)}`,
  );
}

export async function createOverride(
  sessionId: string,
  targetType: "finding" | "incident",
  targetId: string,
  classification: string,
  reason: string,
): Promise<{ ok: boolean; override: OverrideInfo }> {
  return request<{ ok: boolean; override: OverrideInfo }>(
    `/api/sessions/${sessionId}/overrides`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target_type: targetType,
        target_id: targetId,
        classification,
        reason,
      }),
    },
  );
}

// ---------- Fase D: dashboard ----------

export async function getStats(sessionId: string, sheet: string): Promise<DashboardStats> {
  return request<DashboardStats>(
    `/api/sessions/${sessionId}/stats?sheet=${encodeURIComponent(sheet)}`,
  );
}

// ---------- Fase E: redaccion (plantillas + IA con validacion) ----------

export async function getAiSettings(): Promise<AiSettings> {
  return request<AiSettings>("/api/ai/settings");
}

export async function testAiConnection(): Promise<AiTestResult> {
  return request<AiTestResult>("/api/ai/test", { method: "POST" });
}

// Ajustes IA desde la UI (post-F): viven solo en memoria del backend.
export async function updateAiSettings(update: AiSettingsUpdate): Promise<AiSettings> {
  return request<AiSettings>("/api/ai/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(update),
  });
}

export async function resetAiSettings(): Promise<AiSettings> {
  return request<AiSettings>("/api/ai/settings", { method: "DELETE" });
}

export async function generateNarrative(sessionId: string, sheet?: string): Promise<NarrativeResponse> {
  const sp = sheet ? `?sheet=${encodeURIComponent(sheet)}` : "";
  return request<NarrativeResponse>(`/api/sessions/${sessionId}/narrative${sp}`, { method: "POST" });
}

export async function getNarrative(sessionId: string, sheet?: string): Promise<NarrativeResponse> {
  const sp = sheet ? `?sheet=${encodeURIComponent(sheet)}` : "";
  return request<NarrativeResponse>(`/api/sessions/${sessionId}/narrative${sp}`);
}

// ---------- Fase F: informe completo, PDF y exportaciones ----------

export async function getReport(sessionId: string, sheet?: string): Promise<ReportResponse> {
  const sp = sheet ? `?sheet=${encodeURIComponent(sheet)}` : "";
  return request<ReportResponse>(`/api/sessions/${sessionId}/report${sp}`);
}

export async function editReportSection(
  sessionId: string,
  sectionId: string,
  text: string,
  sheet?: string,
): Promise<{ ok: boolean; section: ReportSection }> {
  const sp = sheet ? `?sheet=${encodeURIComponent(sheet)}` : "";
  return request<{ ok: boolean; section: ReportSection }>(
    `/api/sessions/${sessionId}/report/sections/${encodeURIComponent(sectionId)}${sp}`,
    {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    },
  );
}

export async function regenerateReportSection(
  sessionId: string,
  sectionId: string,
  sheet?: string,
): Promise<{ ok: boolean; section: ReportSection }> {
  const sp = sheet ? `?sheet=${encodeURIComponent(sheet)}` : "";
  return request<{ ok: boolean; section: ReportSection }>(
    `/api/sessions/${sessionId}/report/sections/${encodeURIComponent(sectionId)}/regenerate${sp}`,
    { method: "POST" },
  );
}

export async function saveReportMeta(
  sessionId: string,
  meta: { cliente?: string; analista?: string },
  sheet?: string,
): Promise<{ ok: boolean; meta: { cliente: string; analista: string } }> {
  const sp = sheet ? `?sheet=${encodeURIComponent(sheet)}` : "";
  return request<{ ok: boolean; meta: { cliente: string; analista: string } }>(
    `/api/sessions/${sessionId}/report/meta${sp}`,
    {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(meta),
    },
  );
}

// Descargas binarias (PDF/CSV/JSON): blob + enlace temporal para "guardar como".
async function downloadBlob(url: string, fallbackName: string): Promise<void> {
  const res = await fetch(url);
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
  const blob = await res.blob();
  const disposition = res.headers.get("Content-Disposition") || "";
  const match = /filename="?([^";]+)"?/.exec(disposition);
  const name = match ? match[1] : fallbackName;
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(link.href);
}

export function downloadReportPdf(sessionId: string, sheet?: string): Promise<void> {
  const sp = sheet ? `?sheet=${encodeURIComponent(sheet)}` : "";
  return downloadBlob(`/api/sessions/${sessionId}/report/pdf${sp}`, "informe.pdf");
}

export function downloadIocsCsv(sessionId: string, sheet?: string): Promise<void> {
  const sp = sheet ? `?sheet=${encodeURIComponent(sheet)}` : "";
  return downloadBlob(`/api/sessions/${sessionId}/exports/iocs.csv${sp}`, "iocs.csv");
}

export function downloadFindingsJson(sessionId: string, sheet?: string): Promise<void> {
  const sp = sheet ? `?sheet=${encodeURIComponent(sheet)}` : "";
  return downloadBlob(`/api/sessions/${sessionId}/exports/findings.json${sp}`, "hallazgos.json");
}
