"""
api/routes/reports.py

Secure endpoints for viewing and downloading generated PDF reports.
"""

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import FileResponse

from api.config import API_PREFIX, REPORTS_DIR


router = APIRouter(
    prefix=f"{API_PREFIX}/reports",
    tags=["Reports"],
)


def resolve_report_path(report_name: str) -> Path:
    """
    Resolve and validate a requested report path.

    Prevents directory traversal and ensures only PDF files
    inside the configured reports directory can be accessed.
    """

    if not report_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Report name is required.",
        )

    if Path(report_name).name != report_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid report name.",
        )

    if Path(report_name).suffix.lower() != ".pdf":
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Only PDF reports can be accessed.",
        )

    reports_directory = REPORTS_DIR.resolve()
    report_path = (reports_directory / report_name).resolve()

    if report_path.parent != reports_directory:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access to this report path is forbidden.",
        )

    if not report_path.exists() or not report_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Requested report was not found.",
        )

    return report_path


@router.get(
    "/{report_name}",
    summary="View or Download PDF Report",
    response_class=FileResponse,
)
async def get_report(
    report_name: str,
    download: bool = Query(
        default=False,
        description=(
            "Set to true to download the report. "
            "Leave false to view it in the browser."
        ),
    ),
) -> FileResponse:
    """
    View a generated PDF inline or download it explicitly.
    """

    report_path = resolve_report_path(report_name)

    disposition = "attachment" if download else "inline"

    return FileResponse(
        path=report_path,
        media_type="application/pdf",
        filename=report_path.name,
        content_disposition_type=disposition,
    )