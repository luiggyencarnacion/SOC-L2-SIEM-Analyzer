// types.ts - Contratos que consume el frontend (fase A).
export const UNIVERSAL_FIELDS = [
  "log_id", "ts", "host", "user", "src_ip", "dst", "event_code", "msg",
  "cmd", "result", "log_source", "sev_siem", "logon_type", "http",
  "share", "file_path", "bytes_out", "task_service",
] as const;

export type UniversalField = (typeof UNIVERSAL_FIELDS)[number];

export interface MappingEntry {
  column: string;
  field: string | null;
}

export interface SheetPreview {
  name: string;
  data_rows: number;
  data_columns: number;
  header_row: number;
  columns: string[];
  preview_rows: Record<string, unknown>[];
}

export interface UploadResponse {
  session_id: string;
  file_name: string;
  size_bytes: number;
  sheets: SheetPreview[];
  mappings: SheetMapping[];
  warnings: string[];
}

export interface SheetMapping {
  sheet: string;
  header_row: number;
  suggestions: ColumnSuggestion[];
  confidence: number;
}

export interface ColumnSuggestion {
  column: string;
  field: string | null;
  confidence: number;
  rationale: string;
}

export interface EventRow {
  log_id: string;
  row_number: number;
  sheet_name: string;
  timestamp_raw: string | null;
  timestamp_parsed: string | null;
  timestamp_status: string;
  host_raw: string | null;
  host_key: string | null;
  user_raw: string | null;
  user_key: string | null;
  event_code: string | null;
  event_description: string | null;
  source_ip: string | null;
  source_ip_scope: string | null;
  destination_raw: string | null;
  destination_host: string | null;
  destination_ip: string | null;
  log_source: string | null;
  process_command_line: string | null;
  result_raw: string | null;
  result_norm: string | null;
  severity_siem: string | null;
  http_status: number | null;
  url_path: string | null;
  share: string | null;
  file_path: string | null;
  quality_flags: string[];
  raw: { fields?: unknown[] };
  [key: string]: unknown;
}

export interface EventsResponse {
  session_id: string;
  sheet: string;
  total: number;
  page: number;
  page_size: number;
  rows: EventRow[];
}

export interface ColumnQuality {
  column: string;
  populated: number;
  nulls: number;
  null_percent: number;
  distinct: number | null;
}

export interface DataQualityReport {
  total_rows: number;
  columns: ColumnQuality[];
  duplicate_log_ids: string[];
  timestamp: { total: number; missing: number; invalid: number; wall: number; offset: number };
  result_distribution: Record<string, number>;
  mixed_type_columns: string[];
}

export interface AliasRelation {
  kind: string;
  status: string;
  key: string;
  members: string[];
  merged: boolean;
  rationale: string;
}

export interface AnalyzeResponse {
  session_id: string;
  sheet: string;
  total_rows: number;
  quality: DataQualityReport;
  aliases: { hosts: AliasRelation[]; users: AliasRelation[] };
  warnings: string[];
}

export interface RowDetail extends EventRow {
  columns: string[];
}

// ---------- Fase B: deteccion determinista ----------

export interface FindingStatements {
  hecho: string[];
  inferencia: string[];
  hipotesis: string[];
}

export interface Finding {
  finding_id: string;
  rule_id: string;
  rule_name: string;
  category: string;
  severity: string;
  description: string;
  rationale: string;
  mitre: string[];
  entities: {
    users: string[];
    hosts: string[];
    source_ips: string[];
    destinations: string[];
  };
  total_events_matched: number;
  evidence_log_ids: string[];
  total_evidence: number;
  evidence_omitted: number;
  time_range: { start: string | null; end: string | null };
  factors: string[];
  statements: FindingStatements;
  absorbed_detail?: Record<string, unknown>;
  score?: number;
  band?: string;
  base_score?: number;
  factors_applied?: { factor: string; points: number; detail: string }[];
  override?: OverrideInfo | null;
}

export interface DetectionSummary {
  total_rules: number;
  rules_executed: number;
  rules_executed_no_findings: number;
  rules_skipped_disabled: number;
  rules_skipped_missing_fields: number;
  rules_insufficient_data: number;
  rules_error: number;
  total_findings: number;
  findings_by_severity: Record<string, number>;
  elapsed_ms: number;
}

export interface FindingsResponse {
  session_id: string;
  sheet: string;
  total: number;
  summary: DetectionSummary;
  findings: Finding[];
}

export interface CoverageEntry {
  rule_id: string;
  rule_name: string;
  status: string;
  reason: string | null;
  findings: number;
}

export interface CoverageResponse {
  session_id: string;
  sheet: string;
  summary: DetectionSummary;
  coverage: CoverageEntry[];
}

// ---------- Fase C: correlacion, incidentes, scoring y override ----------

export interface OverrideInfo {
  target_type: "finding" | "incident";
  target_id: string;
  classification: string;
  reason: string;
  created_at: string;
}

export interface IncidentTimelineEntry {
  time: string | null;
  finding_id: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  score: number;
  evidence_log_ids: string[];
}

export interface Incident {
  incident_id: string;
  title: string;
  findings: string[];
  score: number;
  band: string;
  max_finding_score: number;
  incident_bonus: number;
  kill_chain_phases: string[];
  mitre: string[];
  timeline: IncidentTimelineEntry[];
  assets: {
    users: string[];
    hosts: string[];
    source_ips: string[];
    destinations: string[];
  };
  iocs: Record<string, string[]>;
  time_range: { start: string | null; end: string | null };
  grouping: {
    shared_entities: Record<string, string[]>;
    max_gap_minutes: number | null;
    window_minutes: number;
    alias_notes: string[];
    justification: string;
  };
  override: OverrideInfo | null;
}

export interface SameAssetRelation {
  incidents: string[];
  shared_hosts: string[];
  conclusion: string;
}

export interface CorrelationResponse {
  session_id: string;
  sheet: string;
  summary: {
    total_incidents: number;
    incidents_by_band: Record<string, number>;
    window_minutes: number;
    findings_assigned: number;
    total_findings: number;
  };
  incidents: Incident[];
  relations: SameAssetRelation[];
}

export const OVERRIDE_CLASSIFICATIONS = ["Crítico", "Alto", "Medio", "Bajo", "Falso positivo"] as const;

// ---------- Fase D: dashboard ----------

export interface StatEntry {
  value: string;
  count: number;
}

export interface DashboardStats {
  session_id: string;
  sheet: string;
  kpis: {
    total_events: number;
    events_with_timestamp: number;
    total_findings: number;
    findings_by_severity: Record<string, number>;
    total_incidents: number;
    incidents_by_band: Record<string, number>;
    affected_users: number;
    affected_hosts: number;
    affected_source_ips: number;
    rules_total: number;
    rules_executed: number;
    rules_skipped: number;
    rules_error: number;
    manual_overrides: number;
    quality_alerts: {
      invalid_timestamps: number;
      missing_timestamps: number;
      invalid_source_ips: number;
      synthetic_log_ids: number;
      duplicate_log_ids: number;
      mixed_type_columns: number;
    };
    time_range: { start: string | null; end: string | null };
  };
  events_timeline: {
    granularity: "hour" | "day";
    buckets: { bucket: string; count: number }[];
    total: number;
  };
  top: {
    source_ips: StatEntry[];
    users: StatEntry[];
    hosts: StatEntry[];
    event_codes: StatEntry[];
    log_sources: StatEntry[];
    siem_severities: StatEntry[];
  };
  siem_vs_calculated: {
    categories: string[];
    siem_events: number[];
    calculated_findings: number[];
  };
  heatmap: {
    days: string[];
    cells: { day: string; hour: number; count: number }[];
    total: number;
  };
  mitre: StatEntry[];
  result_distribution: Record<string, number>;
}

// ---------- Fase E: redaccion por plantillas y IA con anti-alucinacion ----------

export interface AiSettings {
  provider: string;
  effective_provider: string;
  model: string;
  base_url: string;
  key_configured: boolean;
  temperature: number;
  timeout_seconds: number;
  mode: "plantillas" | "ia";
  providers_available: string[];
  settings_source?: "ui" | "env";
}

export interface AiTestResult {
  ok: boolean;
  provider: string;
  effective_provider: string;
  mode: "plantillas" | "ia";
  detail: string;
}

export interface AiSettingsUpdate {
  provider?: string;
  model?: string;
  base_url?: string;
  temperature?: number;
  api_key?: string; // vacia = conservar la actual
  clear_key?: boolean;
}

export interface NarrativeParagraph {
  label: string;
  text: string;
  citations: string[];
  source: "plantilla" | "ia_validada";
}

export interface NarrativeSection {
  section_id: string;
  title: string;
  paragraphs: NarrativeParagraph[];
}

export interface AiState {
  used: boolean;
  provider: string;
  model: string;
  masking: boolean;
  accepted_paragraphs: number;
  rejected: { section: string; reason: string; text_preview?: string }[];
  error: string | null;
}

export interface NarrativeResponse {
  session_id: string;
  sheet: string;
  generated_at: string;
  mode: "plantillas" | "ia";
  total_sections: number;
  total_paragraphs: number;
  sections: NarrativeSection[];
  ai_state: AiState;
}

// ---------- Fase F: informe completo, PDF y exportaciones ----------

export interface ReportParagraph {
  label: string;
  text: string;
  citations: string[];
  source: "plantilla" | "ia_validada" | "manual";
}

export interface ReportTable {
  table_id: string;
  title: string;
  columns: { key: string; label: string }[];
  rows: Record<string, unknown>[];
}

export interface ReportSection {
  number: string;
  section_id: string;
  title: string;
  kind: "texto" | "tabla" | "anexo" | "contenedor" | "hallazgo" | "incidente" | "resumen" | "plan";
  paragraphs: ReportParagraph[];
  tables: ReportTable[];
  editable: boolean;
  edited: boolean;
  edited_at: string | null;
  parent: string | null;
  level: number;
  break_before?: boolean;
  landscape?: boolean;
  cards?: { label: string; value: string | number; hint?: string }[];
  charts?: string[];
  meta?: Record<string, unknown>;
}

export interface ReportResponse {
  session_id: string;
  sheet: string;
  file_name?: string;
  generated_at: string;
  generated_at_human?: string;
  total_sections: number;
  sections: ReportSection[];
  no_evidence_phrase: string;
  meta?: { cliente: string; analista: string };
  band_colors?: Record<string, string>;
}
