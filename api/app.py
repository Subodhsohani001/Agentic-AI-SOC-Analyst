"""
api/app.py

Main FastAPI application for the Agentic AI SOC Analyst.
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from api.config import (
    API_DESCRIPTION,
    API_TITLE,
    API_VERSION,
    ENABLE_REDOC,
    ENABLE_SWAGGER,
)
from api.routes.health import router as health_router
from api.routes.incidents import router as incidents_router
from api.routes.reports import router as reports_router


# ---------------------------------------------------------
# Project Paths
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
INDEX_FILE = FRONTEND_DIR / "index.html"


# ---------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------

app = FastAPI(
    title=API_TITLE,
    description=API_DESCRIPTION,
    version=API_VERSION,
    docs_url="/docs" if ENABLE_SWAGGER else None,
    redoc_url="/redoc" if ENABLE_REDOC else None,
)


# ---------------------------------------------------------
# Frontend Static Files
# ---------------------------------------------------------

app.mount(
    "/static",
    StaticFiles(directory=FRONTEND_DIR),
    name="static",
)


@app.get(
    "/",
    tags=["Frontend"],
    summary="SOC Analyst Web Interface",
    include_in_schema=False,
)
async def root() -> FileResponse:
    """
    Serve the Agentic AI SOC Analyst frontend.
    """

    return FileResponse(INDEX_FILE)


# ---------------------------------------------------------
# Register API Routes
# ---------------------------------------------------------

app.include_router(health_router)
app.include_router(incidents_router)
app.include_router(reports_router)