from __future__ import annotations

import json
import os
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class IncidentStoreError(Exception):
    """Base exception for incident-memory errors."""


class InvalidIncidentError(IncidentStoreError):
    """Raised when an incident does not contain valid data."""


class DuplicateIncidentError(IncidentStoreError):
    """Raised when an incident ID already exists."""


class IncidentStore:
    """
    Deterministic JSON-backed storage for SOC incidents.

    Responsibilities:
    - Load and validate the incident-memory file
    - Generate sequential incident IDs
    - Store incidents safely
    - Prevent duplicate incident IDs
    - Retrieve incidents by ID
    - Return all stored incidents
    """

    SCHEMA_VERSION = "1.0"

    def __init__(self, memory_file: str | Path | None = None) -> None:
        if memory_file is None:
            memory_file = Path(__file__).parent / "incident_memory.json"

        self.memory_file = Path(memory_file)
        self._ensure_memory_file()

    def _default_memory(self) -> dict[str, Any]:
        """Return the default incident-memory structure."""
        return {
            "schema_version": self.SCHEMA_VERSION,
            "incidents": [],
        }

    def _ensure_memory_file(self) -> None:
        """Create the memory directory and JSON file when missing."""
        self.memory_file.parent.mkdir(parents=True, exist_ok=True)

        if not self.memory_file.exists():
            self._atomic_write(self._default_memory())
            return

        if self.memory_file.stat().st_size == 0:
            self._atomic_write(self._default_memory())

    def _load_memory(self) -> dict[str, Any]:
        """Load and validate the complete incident-memory document."""
        try:
            with self.memory_file.open("r", encoding="utf-8") as file:
                memory = json.load(file)
        except json.JSONDecodeError as error:
            raise IncidentStoreError(
                f"Invalid JSON in memory file: {self.memory_file}"
            ) from error
        except OSError as error:
            raise IncidentStoreError(
                f"Unable to read memory file: {self.memory_file}"
            ) from error

        if not isinstance(memory, dict):
            raise IncidentStoreError("Incident memory must be a JSON object.")

        incidents = memory.get("incidents")

        if not isinstance(incidents, list):
            raise IncidentStoreError(
                "Incident memory must contain an 'incidents' list."
            )

        memory.setdefault("schema_version", self.SCHEMA_VERSION)

        return memory

    def _atomic_write(self, memory: dict[str, Any]) -> None:
        """
        Write JSON using a temporary file and atomic replacement.

        This reduces the risk of corrupting incident_memory.json if the
        process stops during a write operation.
        """
        temporary_path: str | None = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.memory_file.parent,
                prefix="incident_memory_",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                json.dump(
                    memory,
                    temporary_file,
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                )
                temporary_file.write("\n")
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
                temporary_path = temporary_file.name

            os.replace(temporary_path, self.memory_file)

        except OSError as error:
            if temporary_path:
                try:
                    Path(temporary_path).unlink(missing_ok=True)
                except OSError:
                    pass

            raise IncidentStoreError(
                f"Unable to write memory file: {self.memory_file}"
            ) from error

    @staticmethod
    def _current_timestamp() -> str:
        """Return the current UTC timestamp in ISO 8601 format."""
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    @staticmethod
    def _validate_incident(incident: dict[str, Any]) -> None:
        """Validate the minimum structure required for an incident."""
        if not isinstance(incident, dict):
            raise InvalidIncidentError("Incident must be a dictionary.")

        if not incident:
            raise InvalidIncidentError("Incident cannot be empty.")

        iocs = incident.get("iocs", {})

        if iocs is not None and not isinstance(iocs, dict):
            raise InvalidIncidentError("'iocs' must be a dictionary.")

        mitre = incident.get("mitre", [])

        if mitre is not None and not isinstance(mitre, list):
            raise InvalidIncidentError("'mitre' must be a list.")

        risk_score = incident.get("risk_score")

        if risk_score is not None:
            if isinstance(risk_score, bool) or not isinstance(
                risk_score, (int, float)
            ):
                raise InvalidIncidentError(
                    "'risk_score' must be a number between 0 and 100."
                )

            if not 0 <= risk_score <= 100:
                raise InvalidIncidentError(
                    "'risk_score' must be between 0 and 100."
                )

    @staticmethod
    def _extract_incident_number(incident_id: str) -> int | None:
        """Extract the numeric part from an ID such as INC-2026-0001."""
        parts = incident_id.split("-")

        if len(parts) != 3:
            return None

        prefix, year, number = parts

        if prefix != "INC":
            return None

        if not year.isdigit() or not number.isdigit():
            return None

        return int(number)

    def generate_incident_id(self) -> str:
        """
        Generate the next sequential incident ID for the current UTC year.

        Example:
            INC-2026-0001
            INC-2026-0002
        """
        memory = self._load_memory()
        current_year = str(datetime.now(timezone.utc).year)
        highest_number = 0

        for incident in memory["incidents"]:
            incident_id = incident.get("incident_id")

            if not isinstance(incident_id, str):
                continue

            parts = incident_id.split("-")

            if len(parts) != 3 or parts[1] != current_year:
                continue

            number = self._extract_incident_number(incident_id)

            if number is not None:
                highest_number = max(highest_number, number)

        return f"INC-{current_year}-{highest_number + 1:04d}"

    def save_incident(
        self,
        incident: dict[str, Any],
        *,
        allow_existing_id: bool = False,
    ) -> dict[str, Any]:
        """
        Validate and save an incident.

        A new incident ID and timestamp are generated when absent.
        The stored incident is returned as a deep copy.
        """
        self._validate_incident(incident)

        memory = self._load_memory()
        stored_incident = deepcopy(incident)

        incident_id = stored_incident.get("incident_id")

        if incident_id is None:
            incident_id = self.generate_incident_id()
            stored_incident["incident_id"] = incident_id

        if not isinstance(incident_id, str) or not incident_id.strip():
            raise InvalidIncidentError(
                "'incident_id' must be a non-empty string."
            )

        existing_ids = {
            item.get("incident_id")
            for item in memory["incidents"]
            if isinstance(item, dict)
        }

        if incident_id in existing_ids and not allow_existing_id:
            raise DuplicateIncidentError(
                f"Incident ID already exists: {incident_id}"
            )

        stored_incident.setdefault("timestamp", self._current_timestamp())

        if allow_existing_id and incident_id in existing_ids:
            memory["incidents"] = [
                stored_incident
                if item.get("incident_id") == incident_id
                else item
                for item in memory["incidents"]
            ]
        else:
            memory["incidents"].append(stored_incident)

        self._atomic_write(memory)

        return deepcopy(stored_incident)

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        """Return an incident by ID, or None when it does not exist."""
        if not isinstance(incident_id, str) or not incident_id.strip():
            raise InvalidIncidentError(
                "'incident_id' must be a non-empty string."
            )

        memory = self._load_memory()

        for incident in memory["incidents"]:
            if incident.get("incident_id") == incident_id:
                return deepcopy(incident)

        return None

    def get_all_incidents(self) -> list[dict[str, Any]]:
        """Return every stored incident."""
        memory = self._load_memory()
        return deepcopy(memory["incidents"])

    def count_incidents(self) -> int:
        """Return the total number of stored incidents."""
        memory = self._load_memory()
        return len(memory["incidents"])

    def incident_exists(self, incident_id: str) -> bool:
        """Check whether an incident ID already exists."""
        return self.get_incident(incident_id) is not None