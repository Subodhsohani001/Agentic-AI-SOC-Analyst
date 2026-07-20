"""
api/routes/health.py

Health check endpoint for the Agentic AI SOC Analyst API.
"""

from datetime import datetime, UTC

from fastapi import APIRouter

from api.config import (
    API_VERSION,
    API_TITLE,
)
from api.schemas.common import HealthResponse


router = APIRouter(
    prefix="/health",
    tags=["Health"],
)


@router.get(
    "",
    response_model=HealthResponse,
    summary="Health Check",
    description="Returns the operational status of the API.",
)
async def health_check() -> HealthResponse:
    """
    Simple endpoint used to verify that the API is running.
    """

    return HealthResponse(
        status="healthy",
        api_version=API_VERSION,
        service=API_TITLE,
        timestamp=datetime.now(UTC),
    )