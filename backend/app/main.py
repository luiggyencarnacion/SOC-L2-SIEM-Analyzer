# main.py - FastAPI SOC L2 SIEM Analyzer (fase A).
# PLAN seccion 11: CORS/host solo localhost, sin secretos, mensajes claros en espanol.
import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes_correlation import router as correlation_router
from app.api.routes_ingestion import router as ingestion_router
from app.core import config

logging.basicConfig(level=config.LOG_LEVEL.upper())
log = logging.getLogger("soc-l2")

app = FastAPI(
    title="SOC L2 SIEM Analyzer",
    version="0.1.0 (fase C)",
    description="Analisis local de logs .xlsx exportados de un SIEM.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(config.ALLOWED_ORIGINS),
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    # Mensajes claros en espanol, sin trazas internas hacia la UI.
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": str(exc.detail)},
    )


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "fase": "C", "bind": f"{config.API_HOST}:{config.API_PORT}"}


app.include_router(ingestion_router)
app.include_router(correlation_router)
