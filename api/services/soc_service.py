"""
api/services/soc_service.py

Service layer that connects FastAPI routes to the existing
SOCOrchestrator without duplicating analysis logic.
"""

from pathlib import Path
from threading import Lock
from typing import Any

from api.config import PROJECT_ROOT
from json_llama import SOCOrchestrator


class SOCService:
    """
    Thread-safe wrapper around the existing SOC orchestrator.
    """

    def __init__(self) -> None:
        self._lock = Lock()

        self._orchestrator = SOCOrchestrator(
            mitre_path=PROJECT_ROOT / "mitre_knowledge.json"
        )

    def analyze_log(
        self,
        log_path: str | Path,
    ) -> dict[str, Any]:
        """
        Analyze a log using the existing v0.1-v0.7 pipeline.
        """
        path = Path(log_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Log file does not exist: {path}"
            )

        if not path.is_file():
            raise ValueError(
                f"Log path is not a file: {path}"
            )

        log_data = path.read_text(
            encoding="utf-8",
            errors="ignore",
        )

        if not log_data.strip():
            raise ValueError(
                f"Log file is empty: {path}"
            )

        with self._lock:
            result = self._orchestrator.process(
                log_data=log_data,
                source_log=path,
            )

        if not isinstance(result, dict):
            raise RuntimeError(
                "SOC orchestrator returned an invalid result."
            )

        return result


soc_service = SOCService()