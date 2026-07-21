"""
api/routes/incidents.py

Incident-analysis endpoints for the Agentic AI SOC Analyst API.
"""

from pathlib import Path
from tempfile import NamedTemporaryFile

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from api.config import (
    API_PREFIX,
    MAX_UPLOAD_SIZE_MB,
    SUPPORTED_LOG_EXTENSIONS,
)
from api.schemas.incidents import IncidentAnalysisResponse
from api.services.soc_service import soc_service


router = APIRouter(
    prefix=f"{API_PREFIX}/incidents",
    tags=["Incidents"],
)


@router.post(
    "/analyze",
    response_model=IncidentAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze Security Log",
    description=(
        "Uploads a supported security log and runs the complete "
        "v0.1-v0.7 Agentic AI SOC investigation pipeline."
    ),
)
async def analyze_incident(
    file: UploadFile = File(...),
) -> IncidentAnalysisResponse:
    """
    Analyze an uploaded security log.
    """

    original_name = file.filename or "uploaded.log"
    extension = Path(original_name).suffix.lower()

    if extension not in SUPPORTED_LOG_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=(
                f"Unsupported file extension: {extension or 'none'}. "
                f"Allowed extensions: "
                f"{', '.join(sorted(SUPPORTED_LOG_EXTENSIONS))}"
            ),
        )

    content = await file.read()

    max_bytes = MAX_UPLOAD_SIZE_MB * 1024 * 1024

    if len(content) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"Uploaded file exceeds the "
                f"{MAX_UPLOAD_SIZE_MB} MB size limit."
            ),
        )

    if not content.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded log file is empty.",
        )

    temporary_path: Path | None = None

    try:
        with NamedTemporaryFile(
            mode="wb",
            suffix=extension,
            prefix="soc_upload_",
            delete=False,
        ) as temporary_file:
            temporary_file.write(content)
            temporary_path = Path(temporary_file.name)

        result = soc_service.analyze_log(
            temporary_path
        )

        if not isinstance(result, dict):
            raise RuntimeError(
                "SOC service returned an invalid result."
            )

        analysis = result.get(
            "analysis",
            {},
        )

        if not isinstance(analysis, dict):
            analysis = {}

        response = result.get(
            "response",
            {},
        )

        if not isinstance(response, dict):
            response = {}

        extracted_facts = analysis.get(
            "extracted_facts",
            {},
        )

        if not isinstance(extracted_facts, dict):
            extracted_facts = {}

        multi_agent = result.get(
            "multi_agent",
            {},
        )

        if not isinstance(multi_agent, dict):
            multi_agent = {}

        multi_agent_report = multi_agent.get(
            "report",
            {},
        )

        if not isinstance(multi_agent_report, dict):
            multi_agent_report = {}

        completion = multi_agent_report.get(
            "completion_assessment",
            {},
        )

        if not isinstance(completion, dict):
            completion = {}

        response_decision = response.get(
            "decision",
            {},
        )

        if not isinstance(response_decision, dict):
            response_decision = {}

        response_plan = response.get(
            "plan",
            {},
        )

        if not isinstance(response_plan, dict):
            response_plan = {}

        approval_requests = response.get(
            "approval_requests",
            [],
        )

        if not isinstance(approval_requests, list):
            approval_requests = []

        execution_results = response.get(
            "execution_results",
            [],
        )

        if not isinstance(execution_results, list):
            execution_results = []

        mitre_attack = analysis.get(
            "mitre_attack",
            {},
        )

        if not isinstance(mitre_attack, dict):
            mitre_attack = {}

        report_path_value = result.get(
            "report_path"
        )

        report_name: str | None = None

        if report_path_value:
            report_name = Path(
                str(report_path_value)
            ).name

        if report_path_value:
            report_name = Path(str(report_path_value)).name

        return IncidentAnalysisResponse(
            success=True,
            message="Security log analyzed successfully.",
            incident_id=analysis.get(
                "incident_id"
            ),
            severity=analysis.get(
                "severity"
            ),
            attack_type=analysis.get(
                "attack_type"
            ),
            confidence=analysis.get(
                "confidence"
            ),
            source_ip=analysis.get(
                "source_ip"
            ),
            mitre_attack=mitre_attack,
            ioc_summary={
                "ip_addresses": len(
                    extracted_facts.get(
                        "ip_addresses",
                        [],
                    )
                ),
                "domains": len(
                    extracted_facts.get(
                        "domains",
                        [],
                    )
                ),
                "urls": len(
                    extracted_facts.get(
                        "urls",
                        [],
                    )
                ),
                "hashes": len(
                    extracted_facts.get(
                        "hashes",
                        [],
                    )
                ),
                "files": len(
                    extracted_facts.get(
                        "file_names",
                        [],
                    )
                ),
            },
            investigation_summary={
                "status": completion.get(
                    "readiness"
                ),
                "confirmed_hypotheses": completion.get(
                    "confirmed_hypothesis_count",
                    0,
                ),
                "incomplete_tasks": completion.get(
                    "incomplete_task_count",
                    0,
                ),
                "failed_tasks": completion.get(
                    "failed_task_count",
                    0,
                ),
                "root_cause_available": completion.get(
                    "root_cause_present",
                    False,
                ),
                "response_advisory_available": completion.get(
                    "response_advisory_present",
                    False,
                ),
            },
            response_summary={
                "mode": response.get(
                    "mode"
                ),
                "priority": response_decision.get(
                    "priority"
                ),
                "plan_id": response_plan.get(
                    "plan_id"
                ),
                "plan_status": response_plan.get(
                    "status"
                ),
                "approval_request_count": len(
                    approval_requests
                ),
                "execution_result_count": len(
                    execution_results
                ),
            },
            artifacts={
                "report_name": report_name,
                "view_url": (
                    f"{API_PREFIX}/reports/{report_name}"
                    if report_name
                    else None
                ),
                "download_url": (
                    f"{API_PREFIX}/reports/{report_name}?download=true"
                    if report_name
                    else None
                ),
                "multi_agent_report": result.get(
                    "multi_agent_report_path"
                ),
                "audit_log": response.get(
                    "audit_log_path"
                ),
            },
        )

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                f"Incident analysis failed: "
                f"{type(exc).__name__}: {exc}"
            ),
        ) from exc

    finally:
        await file.close()

        if temporary_path is not None:
            try:
                temporary_path.unlink(
                    missing_ok=True
                )
            except OSError:
                pass