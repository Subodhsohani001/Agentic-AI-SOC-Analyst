"""
api/app.py

Main FastAPI application for the Agentic AI SOC Analyst.
"""

from fastapi import FastAPI

from api.routes.incidents import router as incidents_router

from api.config import (
    API_DESCRIPTION,
    API_TITLE,
    API_VERSION,
    ENABLE_REDOC,
    ENABLE_SWAGGER,
)
from api.routes.health import router as health_router



app = FastAPI(
    title=API_TITLE,
    description=API_DESCRIPTION,
    version=API_VERSION,
    docs_url="/docs" if ENABLE_SWAGGER else None,
    redoc_url="/redoc" if ENABLE_REDOC else None,
)


@app.get(
    "/",
    tags=["Root"],
    summary="Root Endpoint",
)
async def root() -> dict[str, str]:
    """
    Root endpoint for the API.
    """

    return {
        "message": (
            "Welcome to the Agentic AI SOC Analyst API. "
            "Visit /docs to explore the API."
        )
    }


# ---------------------------------------------------------
# Register API Routes
# ---------------------------------------------------------

app.include_router(health_router)

app.include_router(incidents_router)