"""
api/schemas/common.py

Shared Pydantic models used throughout the API.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class APIResponse(BaseModel):
    """
    Generic API response.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
    )

    success: bool = Field(
        description="Whether the request completed successfully."
    )

    message: str = Field(
        description="Human-readable response message."
    )

    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="UTC timestamp when the response was generated.",
    )


class ErrorResponse(BaseModel):
    """
    Standard API error response.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
    )

    success: bool = False

    error: str

    details: dict[str, Any] | None = None

    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
    )


class HealthResponse(BaseModel):
    """
    Response returned by the health endpoint.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
    )

    status: str

    api_version: str

    service: str

    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
    )