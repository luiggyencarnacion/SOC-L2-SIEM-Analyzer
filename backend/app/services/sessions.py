# services/sessions.py - Store de sesiones en memoria (fase A).
# PLAN: sesion en memoria + archivos temporales en data/uploads (git-ignorada).
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core import config


@dataclass
class SheetData:
    name: str
    header_row_idx: int      # indice (0-based) de la fila de cabecera
    columns: List[str]
    rows: List[List[Any]]    # filas de datos (sin cabecera), acotadas a MAX_COLUMNAS
    preview_rows: List[List[Any]]


@dataclass
class AnalysisResult:
    sheet: str
    header_row_idx: int
    columns: List[str]
    field_map: Dict[str, int]          # campo universal -> indice de columna
    log_id_column: Optional[int]
    events: List[Dict[str, Any]] = field(default_factory=list)
    quality: Dict[str, Any] = field(default_factory=dict)
    detection: Dict[str, Any] = field(default_factory=dict)
    correlation: Dict[str, Any] = field(default_factory=dict)
    # Redaccion de secciones (fase E): plantillas deterministas y/o IA validada.
    narrative: Optional[Dict[str, Any]] = None
    # Override manual (fase C): "finding:F-001" / "incident:I-002" -> clasificacion + motivo.
    overrides: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class SessionData:
    session_id: str
    file_name: str
    file_path: Path
    size_bytes: int
    sheets: Dict[str, SheetData]
    suggestions: Dict[str, List[Dict[str, Any]]]  # por hoja
    analyses: Dict[str, AnalysisResult] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


_lock = threading.Lock()
_sessions: Dict[str, SessionData] = {}


def create_session(
    file_name: str,
    file_path: Path,
    size_bytes: int,
    sheets: Dict[str, SheetData],
    suggestions: Dict[str, List[Dict[str, Any]]],
    warnings: List[str],
) -> SessionData:
    with _lock:
        # Tope de sesiones: expulsa la mas antigua (orden de insercion).
        while len(_sessions) >= config.MAX_SESSIONS:
            oldest_key = next(iter(_sessions))
            _sessions.pop(oldest_key, None)
        sid = str(uuid.uuid4())
        data = SessionData(
            session_id=sid,
            file_name=file_name,
            file_path=file_path,
            size_bytes=size_bytes,
            sheets=sheets,
            suggestions=suggestions,
            warnings=warnings,
        )
        _sessions[sid] = data
    return data


def get_session(session_id: str) -> Optional[SessionData]:
    return _sessions.get(session_id)


def delete_session(session_id: str) -> bool:
    with _lock:
        data = _sessions.pop(session_id, None)
    if data is None:
        return False
    try:
        if data.file_path.exists():
            data.file_path.unlink()
    except OSError:
        pass
    return True
