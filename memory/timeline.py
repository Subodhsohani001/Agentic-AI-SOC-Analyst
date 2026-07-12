from __future__ import annotations

from datetime import datetime
from typing import Any

from memory.incident_store import IncidentStore


class TimelineError(Exception):
    """Base exception for timeline-processing errors."""


class InvalidTimelineInputError(TimelineError):
    """Raised when timeline input is invalid."""


class IncidentTimeline:
    """
    Builds deterministic historical timelines from stored incidents.

    Supported timeline views:
    - IOC timeline
    - MITRE technique timeline
    - Incident chronology
    - Repeat-offender summary
    """

    def __init__(self, incident_store: IncidentStore | None = None) -> None:
        self.incident_store = incident_store or IncidentStore()

    @staticmethod
    def _normalize_string(value: Any) -> str | None:
        if value is None:
            return None

        normalized = str(value).strip().lower()

        return normalized if normalized else None

    @classmethod
    def _normalize_collection(cls, values: Any) -> set[str]:
        if values is None:
            return set()

        if isinstance(values, str):
            values = [values]

        if not isinstance(values, (list, tuple, set)):
            return set()

        normalized_values: set[str] = set()

        for value in values:
            normalized = cls._normalize_string(value)

            if normalized is not None:
                normalized_values.add(normalized)

        return normalized_values

    @staticmethod
    def _parse_timestamp(timestamp: Any) -> datetime | None:
        """
        Parse ISO 8601 timestamps safely.

        Supports timestamps ending in:
        - +00:00
        - Z
        """
        if not isinstance(timestamp, str):
            return None

        cleaned = timestamp.strip()

        if not cleaned:
            return None

        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"

        try:
            return datetime.fromisoformat(cleaned)
        except ValueError:
            return None

    @classmethod
    def _incident_sort_key(
        cls,
        incident: dict[str, Any],
    ) -> tuple[datetime, str]:
        """
        Return a stable chronological sort key.

        Invalid timestamps are placed at the beginning.
        """
        timestamp = cls._parse_timestamp(
            incident.get("timestamp")
        )

        if timestamp is None:
            timestamp = datetime.min

        incident_id = str(
            incident.get("incident_id", "")
        )

        return timestamp, incident_id

    @classmethod
    def _extract_iocs(
        cls,
        incident: dict[str, Any],
    ) -> dict[str, set[str]]:
        iocs = incident.get("iocs", {})

        if not isinstance(iocs, dict):
            return {}

        normalized_iocs: dict[str, set[str]] = {}

        for ioc_type, values in iocs.items():
            normalized_type = cls._normalize_string(ioc_type)

            if normalized_type is None:
                continue

            normalized_values = cls._normalize_collection(values)

            if normalized_values:
                normalized_iocs[normalized_type] = normalized_values

        return normalized_iocs

    @classmethod
    def _extract_mitre(
        cls,
        incident: dict[str, Any],
    ) -> set[str]:
        techniques = cls._normalize_collection(
            incident.get("mitre", [])
        )

        return {
            technique.upper()
            for technique in techniques
        }

    @staticmethod
    def _validate_text_value(
        value: Any,
        field_name: str,
    ) -> str:
        if not isinstance(value, str) or not value.strip():
            raise InvalidTimelineInputError(
                f"'{field_name}' must be a non-empty string."
            )

        return value.strip()

    def get_incident_chronology(
        self,
        *,
        maximum_results: int | None = None,
        newest_first: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Return all stored incidents in chronological order.
        """
        if maximum_results is not None:
            if (
                isinstance(maximum_results, bool)
                or not isinstance(maximum_results, int)
                or maximum_results < 1
            ):
                raise InvalidTimelineInputError(
                    "'maximum_results' must be a positive integer or None."
                )

        incidents = self.incident_store.get_all_incidents()

        incidents.sort(
            key=self._incident_sort_key,
            reverse=newest_first,
        )

        chronology = [
            {
                "incident_id": incident.get("incident_id"),
                "timestamp": incident.get("timestamp"),
                "severity": incident.get("severity"),
                "risk_score": incident.get("risk_score"),
                "source": incident.get("source"),
            }
            for incident in incidents
        ]

        if maximum_results is not None:
            chronology = chronology[:maximum_results]

        return chronology

    def build_ioc_timeline(
        self,
        ioc_value: str,
        *,
        ioc_type: str | None = None,
    ) -> dict[str, Any]:
        """
        Build a historical timeline for one IOC value.

        When ioc_type is provided, only that category is searched.
        """
        normalized_value = self._normalize_string(
            self._validate_text_value(
                ioc_value,
                "ioc_value",
            )
        )

        normalized_type = None

        if ioc_type is not None:
            normalized_type = self._normalize_string(
                self._validate_text_value(
                    ioc_type,
                    "ioc_type",
                )
            )

        occurrences: list[dict[str, Any]] = []

        for incident in self.incident_store.get_all_incidents():
            incident_iocs = self._extract_iocs(incident)

            matched_types: list[str] = []

            for stored_type, stored_values in incident_iocs.items():
                if (
                    normalized_type is not None
                    and stored_type != normalized_type
                ):
                    continue

                if normalized_value in stored_values:
                    matched_types.append(stored_type)

            if not matched_types:
                continue

            occurrences.append(
                {
                    "incident_id": incident.get("incident_id"),
                    "timestamp": incident.get("timestamp"),
                    "ioc_types": sorted(matched_types),
                    "severity": incident.get("severity"),
                    "risk_score": incident.get("risk_score"),
                    "source": incident.get("source"),
                }
            )

        occurrences.sort(
            key=self._incident_sort_key
        )

        valid_timestamps = [
            occurrence["timestamp"]
            for occurrence in occurrences
            if self._parse_timestamp(
                occurrence.get("timestamp")
            )
            is not None
        ]

        first_seen = (
            valid_timestamps[0]
            if valid_timestamps
            else None
        )

        last_seen = (
            valid_timestamps[-1]
            if valid_timestamps
            else None
        )

        return {
            "ioc": normalized_value,
            "ioc_type_filter": normalized_type,
            "occurrence_count": len(occurrences),
            "is_repeat_offender": len(occurrences) > 1,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "timeline": occurrences,
        }

    def build_mitre_timeline(
        self,
        technique_id: str,
    ) -> dict[str, Any]:
        """
        Build a historical timeline for one MITRE technique.
        """
        validated_technique = self._validate_text_value(
            technique_id,
            "technique_id",
        )

        normalized_technique = validated_technique.upper()

        occurrences: list[dict[str, Any]] = []

        for incident in self.incident_store.get_all_incidents():
            techniques = self._extract_mitre(incident)

            if normalized_technique not in techniques:
                continue

            occurrences.append(
                {
                    "incident_id": incident.get("incident_id"),
                    "timestamp": incident.get("timestamp"),
                    "severity": incident.get("severity"),
                    "risk_score": incident.get("risk_score"),
                    "source": incident.get("source"),
                }
            )

        occurrences.sort(
            key=self._incident_sort_key
        )

        valid_timestamps = [
            occurrence["timestamp"]
            for occurrence in occurrences
            if self._parse_timestamp(
                occurrence.get("timestamp")
            )
            is not None
        ]

        return {
            "technique_id": normalized_technique,
            "occurrence_count": len(occurrences),
            "is_repeated": len(occurrences) > 1,
            "first_seen": (
                valid_timestamps[0]
                if valid_timestamps
                else None
            ),
            "last_seen": (
                valid_timestamps[-1]
                if valid_timestamps
                else None
            ),
            "timeline": occurrences,
        }

    def get_repeat_offenders(
        self,
        *,
        minimum_occurrences: int = 2,
    ) -> list[dict[str, Any]]:
        """
        Return IOC values observed in multiple incidents.
        """
        if (
            isinstance(minimum_occurrences, bool)
            or not isinstance(minimum_occurrences, int)
            or minimum_occurrences < 2
        ):
            raise InvalidTimelineInputError(
                "'minimum_occurrences' must be an integer of at least 2."
            )

        index: dict[
            tuple[str, str],
            list[dict[str, Any]],
        ] = {}

        for incident in self.incident_store.get_all_incidents():
            incident_iocs = self._extract_iocs(incident)

            for ioc_type, values in incident_iocs.items():
                for value in values:
                    key = (ioc_type, value)

                    index.setdefault(key, []).append(
                        {
                            "incident_id": incident.get(
                                "incident_id"
                            ),
                            "timestamp": incident.get(
                                "timestamp"
                            ),
                            "severity": incident.get(
                                "severity"
                            ),
                            "risk_score": incident.get(
                                "risk_score"
                            ),
                        }
                    )

        repeat_offenders: list[dict[str, Any]] = []

        for (
            ioc_type,
            ioc_value,
        ), occurrences in index.items():
            if len(occurrences) < minimum_occurrences:
                continue

            occurrences.sort(
                key=self._incident_sort_key
            )

            valid_timestamps = [
                occurrence["timestamp"]
                for occurrence in occurrences
                if self._parse_timestamp(
                    occurrence.get("timestamp")
                )
                is not None
            ]

            repeat_offenders.append(
                {
                    "ioc_type": ioc_type,
                    "ioc": ioc_value,
                    "occurrence_count": len(
                        occurrences
                    ),
                    "first_seen": (
                        valid_timestamps[0]
                        if valid_timestamps
                        else None
                    ),
                    "last_seen": (
                        valid_timestamps[-1]
                        if valid_timestamps
                        else None
                    ),
                    "incident_ids": [
                        occurrence.get("incident_id")
                        for occurrence in occurrences
                    ],
                    "occurrences": occurrences,
                }
            )

        repeat_offenders.sort(
            key=lambda item: (
                -item["occurrence_count"],
                item["ioc_type"],
                item["ioc"],
            )
        )

        return repeat_offenders

    def build_summary(self) -> dict[str, Any]:
        """
        Build a complete historical summary for reporting.
        """
        incidents = self.incident_store.get_all_incidents()

        all_iocs: set[tuple[str, str]] = set()
        all_techniques: set[str] = set()

        for incident in incidents:
            for ioc_type, values in self._extract_iocs(
                incident
            ).items():
                for value in values:
                    all_iocs.add(
                        (ioc_type, value)
                    )

            all_techniques.update(
                self._extract_mitre(incident)
            )

        repeat_offenders = self.get_repeat_offenders(
            minimum_occurrences=2
        )

        chronology = self.get_incident_chronology()

        return {
            "total_incidents": len(incidents),
            "unique_ioc_count": len(all_iocs),
            "unique_mitre_technique_count": len(
                all_techniques
            ),
            "repeat_offender_count": len(
                repeat_offenders
            ),
            "repeat_offenders": repeat_offenders,
            "incident_chronology": chronology,
        }