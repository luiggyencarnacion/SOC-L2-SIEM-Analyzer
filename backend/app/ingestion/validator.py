# ingestion/validator.py - Validacion de archivos subidos (fase A).
# Reglas (PLAN seccion 5 y 11):
# - Solo .xlsx: rechazo .xls/.xlsm y todo lo demas.
# - Firma ZIP (PK) + estructura interna legible; nunca se ejecutan macros ni formulas.
# - Limites de tamano/hojas/columnas/filas configurables.
from typing import Any, Dict, List, Tuple

import openpyxl
from openpyxl.utils import get_column_letter

from app.core import config

MAX_UPLOAD_BYTES = config.MAX_UPLOAD_MB * 1024 * 1024


class UploadError(Exception):
    """Error de validacion con mensaje apto para la UI (en espanol)."""


def validate_extension(file_name: str) -> str:
    """Devuelve el nombre sanitizado si la extension es .xlsx; si no, lanza error."""
    safe_name = (file_name or "").replace("\\", "/").split("/")[-1].strip() or "archivo.xlsx"
    if safe_name.lower().endswith(".xlsm"):
        raise UploadError("Solo se aceptan archivos .xlsx; los .xlsm (macros) se rechazan por seguridad.")
    if not safe_name.lower().endswith(".xlsx"):
        raise UploadError("Formato no aceptado: solo archivos .xlsx (.xls, .csv y otros se rechazan).")
    return safe_name


def validate_signature_and_size(data: bytes) -> None:
    """Verifica tamano y firma ZIP antes de abrir con openpyxl."""
    if len(data) == 0:
        raise UploadError("El archivo esta vacio.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise UploadError(f"El archivo supera el limite de {config.MAX_UPLOAD_MB} MB.")
    if not data[:2] == b"PK":
        raise UploadError("El archivo no tiene firma XLSX valida (no es un .xlsx real).")


def validate_no_macros(data: bytes) -> None:
    """El paquete XLSX no debe incluir VBA (vbaProject.bin)."""
    import io
    import zipfile

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
    except zipfile.BadZipFile:
        raise UploadError("El archivo esta corrupto (ZIP invalido).")
    if any("vbaProject.bin" in n for n in names):
        raise UploadError("El archivo contiene macros; por seguridad no se procesa.")


def load_workbook_sheets(data: bytes) -> Dict[str, List[List[Any]]]:
    """Abre el XLSX en modo lectura (sin formulas ejecutadas) y devuelve celdas por hoja.

    Devuelve {nombre_hoja: filas_de_celdas}. data_only=True devuelve el valor
    cacheado de las formulas, jamas se evalua nada.
    """
    import io

    try:
        wb = openpyxl.load_workbook(
            io.BytesIO(data), read_only=True, data_only=True, keep_links=False
        )
    except openpyxl.utils.exceptions.InvalidFileException:
        raise UploadError("El archivo no puede leerse como XLSX.")
    except Exception:
        raise UploadError("El archivo esta corrupto o cifrado y no puede abrirse.")

    if len(wb.sheetnames) == 0:
        raise UploadError("El archivo no contiene hojas.")
    if len(wb.sheetnames) > config.MAX_SHEETS:
        raise UploadError(f"El archivo supera el limite de {config.MAX_SHEETS} hojas.")

    sheets: Dict[str, List[List[Any]]] = {}
    for name in wb.sheetnames:
        ws = wb[name]
        rows: List[List[Any]] = []
        for row in ws.iter_rows(values_only=True):
            if len(row) > config.MAX_COLUMNS:
                rows.append(list(row[: config.MAX_COLUMNS]))
                continue
            rows.append(list(row))
            if len(rows) > config.MAX_ROWS + 2:  # margen para la cabecera
                break
        # Estructura minima: al menos dos filas con datos.
        non_empty = [r for r in rows if any(c is not None for c in r)]
        if len(non_empty) < 2:
            sheets[name] = rows
            continue
        sheets[name] = rows
    wb.close()

    if all(not [_f for _f in _r if _f is not None] for _rows in sheets.values() for _r in _rows):
        raise UploadError("El archivo no contiene datos legibles.")
    return sheets


def check_min_structure(columns: List[str], total_rows: int) -> List[str]:
    """Advertencias de estructura minima: timestamp + al menos una identidad."""
    warnings: List[str] = []
    focused = [c.lower() for c in columns]
    has_ts = any("timestamp" in c or "fecha" in c or "hora" in c or c in ("date", "time") for c in focused)
    has_identity = any(
        token in c for c in focused for token in ("user", "usuario", "host", "hostname", "equipo", "ip", "cuenta")
    )
    if not has_ts:
        warnings.append("No se detecta columna de timestamp en el mapeo automatico; revisa el mapeo manual.")
    if not has_identity:
        warnings.append("No se detecta columna de identidad (usuario/host/IP); revisa el mapeo manual.")
    return warnings


def sheet_dimensions(rows: List[List[Any]]) -> Tuple[int, int]:
    """(filas, columnas) rapidas para mostrar dimensiones en la UI."""
    max_col = 0
    for r in rows:
        for i, _ in enumerate(r):
            if r[i] is not None:
                max_col = max(max_col, i + 1)
    return len(rows), max_col


def column_letters(n: int) -> List[str]:
    return [get_column_letter(i + 1) for i in range(n)]
