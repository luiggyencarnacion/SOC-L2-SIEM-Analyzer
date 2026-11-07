# tests/test_validator.py - Validacion de archivos subidos (fase A).
import io
import zipfile
from pathlib import Path

import pytest

from app.ingestion import validator
from app.ingestion.validator import UploadError

SAMPLE = Path(__file__).resolve().parents[2] / "data" / "sample" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"


def test_rejects_non_xlsx_extension():
    for bad in ("export.csv", "export.xls", "export", "export.xlsx.exe"):
        with pytest.raises(UploadError):
            validator.validate_extension(bad)


def test_rejects_xlsm():
    with pytest.raises(UploadError):
        validator.validate_extension("export.xlsm")


def test_rejects_empty_and_bad_signature():
    with pytest.raises(UploadError):
        validator.validate_signature_and_size(b"")
    with pytest.raises(UploadError):
        validator.validate_signature_and_size(b"not a zip file at all........")


def test_rejects_zip_with_macros():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("xl/vbaProject.bin", b"macro")
        zf.writestr("[Content_Types].xml", b"<Types/>")
    with pytest.raises(UploadError):
        validator.validate_no_macros(buf.getvalue())


def test_sample_loads_and_has_sheets():
    sheets = validator.load_workbook_sheets(SAMPLE.read_bytes())
    assert len(sheets) >= 1
    for name, rows in sheets.items():
        assert isinstance(rows, list)
