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
