"""
api/schemas/incidents.py

Pydantic models for incident-analysis API responses.
"""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ArtifactPaths(BaseModel):
    """Generated investigation artifacts."""

    model_config = ConfigDict(extra="forbid")

    report_name: str | None = None
    view_url: str | None = None
    download_url: str | None = None

    multi_agent_report: str | None = None
    audit_log: str | None = None


class IncidentAnalysisResponse(BaseModel):
    """Clean response returned after analyzing a security log."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
    )

    success: bool = True
    message: str

    incident_id: str | None = None
    severity: str | None = None
    attack_type: str | None = None
    confidence: str | None = None
    source_ip: str | None = None

    mitre_attack: dict[str, Any] = Field(
        default_factory=dict
    )

    ioc_summary: dict[str, int] = Field(
        default_factory=dict
    )

    investigation_summary: dict[str, Any] = Field(
        default_factory=dict
    )

    response_summary: dict[str, Any] = Field(
        default_factory=dict
    )

    artifacts: ArtifactPaths = Field(
        default_factory=ArtifactPaths
    )

    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC)
    )