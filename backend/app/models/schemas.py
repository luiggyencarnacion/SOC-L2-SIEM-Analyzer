# models/schemas.py - Contratos de la API para la fase A.
# Solo estructuras; sin valores del ejemplo hardcodeados.
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

# Campos universales normalizados (PLAN seccion 4.1 y 6.1).
UNIVERSAL_FIELDS = [
    "log_id", "ts", "host", "user", "src_ip", "dst", "event_code", "msg",
    "cmd", "result", "log_source", "sev_siem", "logon_type", "http",
    "share", "file_path", "bytes_out", "task_service",
]
REQUIRED_HINT_FIELDS = ("ts",)  # se requiere ts + al menos una identidad


class SheetPreview(BaseModel):
    name: str
    data_rows: int
    data_columns: int
    header_row: int
    columns: List[str]
    preview_rows: List[Dict[str, Any]] = Field(description="Hasta 5 filas crudas")


class MappingEntry(BaseModel):
    column: str
    field: Optional[str] = None


class ColumnSuggestion(BaseModel):
    column: str
    field: Optional[str] = None
    confidence: float = Field(ge=0, le=1)
    rationale: str


class SheetMapping(BaseModel):
    sheet: str
    header_row: int
    suggestions: List[ColumnSuggestion]
    confidence: float


class UploadResponse(BaseModel):
    session_id: str
    file_name: str
    size_bytes: int
    sheets: List[SheetPreview]
    mappings: List[SheetMapping]
    warnings: List[str]


class AnalyzeRequest(BaseModel):
    sheet: str
    header_row: int = 1
    mapping: List[MappingEntry]


class TimestampSummary(BaseModel):
    total: int
    missing: int
    invalid: int
    wall: int
    offset: int


class ColumnQuality(BaseModel):
    column: str
    populated: int
    nulls: int
    null_percent: float
    distinct: Optional[int] = None


class DataQualityReport(BaseModel):
    total_rows: int
    columns: List[ColumnQuality]
    duplicate_log_ids: List[str]
    timestamp: TimestampSummary
    result_distribution: Dict[str, int]
    mixed_type_columns: List[str]


class AliasRelation(BaseModel):
    kind: Literal["host", "user"]
    status: Literal["exact", "probable", "candidate"]
    key: str
    members: List[str]
    merged: bool
    rationale: str


class AliasReport(BaseModel):
    hosts: List[AliasRelation]
    users: List[AliasRelation]


class AnalyzeResponse(BaseModel):
    session_id: str
    sheet: str
    total_rows: int
    quality: DataQualityReport
    aliases: AliasReport


class EventsResponse(BaseModel):
    session_id: str
    sheet: str
    total: int
    page: int
    page_size: int
    rows: List[Dict[str, Any]]


class SessionInfo(BaseModel):
    session_id: str
    file_name: str
    size_bytes: int
    sheets: List[str]
    analyzed: Dict[str, int]  # hoja -> filas normalizadas
