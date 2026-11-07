# core/config.py - Configuracion desde .env / variables de entorno.
# Sin secretos en el codigo; limites configurables (PLAN seccion 5 y 11).
from pathlib import Path

import os

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parents[2]  # backend/
ROOT_DIR = BASE_DIR.parent

load_dotenv(BASE_DIR / ".env")

LOG_LEVEL = os.getenv("LOG_LEVEL", "info")

# --- Limites de ingestas (PLAN seccion 5) ---
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "25"))
MAX_SHEETS = int(os.getenv("MAX_SHEETS", "50"))
MAX_ROWS = int(os.getenv("MAX_ROWS", "100000"))
MAX_COLUMNS = int(os.getenv("MAX_COLUMNS", "100"))

# --- Direccionamiento (PLAN: solo localhost) ---
API_HOST = "127.0.0.1"
API_PORT = int(os.getenv("API_PORT", "8000"))
ALLOWED_ORIGINS = [
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:4173",
    "http://localhost:4173",
]

# --- Carpetas de datos (git-ignoradas) ---
DATA_DIR = ROOT_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
EXPORT_DIR = DATA_DIR / "exports"
SESSION_DIR = DATA_DIR / "sessions"

# --- Gestion del ciclo de vida de sesiones en memoria ---
MAX_SESSIONS = int(os.getenv("MAX_SESSIONS", "10"))

for _d in (UPLOAD_DIR, EXPORT_DIR, SESSION_DIR):
    _d.mkdir(parents=True, exist_ok=True)
