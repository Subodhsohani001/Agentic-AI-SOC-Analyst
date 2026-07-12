from __future__ import annotations

from copy import deepcopy
from typing import Any

from memory.incident_store import IncidentStore


class CorrelationEngineError(Exception):
    """Base exception for correlation-engine errors."""


class InvalidCorrelationInputError(CorrelationEngineError):
    """Raised when an incident cannot be correlated safely."""


class CorrelationEngine:
    """
    Deterministic incident-correlation engine.

    Correlation signals:
    - IOC overlap
    - MITRE ATT&CK technique overlap
    - Detection overlap

    The engine does not perform threat-actor attribution.
    It only reports evidence found in stored incidents.
    """

    IOC_TYPES = (
        "ips",
        "domains",
        "urls",
        "hashes",
        "emails",
        "files",
    )

    IOC_WEIGHT = 0.50
    MITRE_WEIGHT = 0.30
    DETECTION_WEIGHT = 0.20

    DEFAULT_MINIMUM_SCORE = 1.0

    def __init__(self, incident_store: IncidentStore | None = None) -> None:
        self.incident_store = incident_store or IncidentStore()

    @staticmethod
    def _normalize_string(value: Any) -> str | None:
        """
        Normalize a comparable string value.

        Normalization is intentionally conservative:
        - Convert to string
        - Remove surrounding whitespace
        - Convert to lowercase
        """
        if value is None:
            return None

        normalized = str(value).strip().lower()

        return normalized if normalized else None

    @classmethod
    def _normalize_collection(cls, values: Any) -> set[str]:
        """Convert a list-like value into a normalized string set."""
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

    @classmethod
    def _extract_iocs(cls, incident: dict[str, Any]) -> dict[str, set[str]]:
        """Extract normalized IOC values, grouped by IOC type."""
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
    def _extract_mitre(cls, incident: dict[str, Any]) -> set[str]:
        """Extract normalized MITRE ATT&CK technique IDs."""
        mitre_values = incident.get("mitre", [])

        normalized = cls._normalize_collection(mitre_values)

        return {technique.upper() for technique in normalized}

    @classmethod
    def _extract_detections(cls, incident: dict[str, Any]) -> set[str]:
        """Extract normalized detection names."""
        return cls._normalize_collection(incident.get("detections", []))

    @staticmethod
    def _validate_incident(incident: dict[str, Any]) -> None:
        """Validate input before correlation."""
        if not isinstance(incident, dict):
            raise InvalidCorrelationInputError(
                "Incident must be provided as a dictionary."
            )

        if not incident:
            raise InvalidCorrelationInputError(
                "Incident cannot be empty."
            )

    @staticmethod
    def _jaccard_similarity(
        current_values: set[str],
        historical_values: set[str],
    ) -> float:
        """
        Calculate deterministic Jaccard similarity.

        Formula:
            intersection size / union size

        Returns a value between 0.0 and 1.0.
        """
        union = current_values | historical_values

        if not union:
            return 0.0

        intersection = current_values & historical_values

        return len(intersection) / len(union)

    @classmethod
    def _compare_iocs(
        cls,
        current_incident: dict[str, Any],
        historical_incident: dict[str, Any],
    ) -> dict[str, Any]:
        """Compare IOC values while preserving IOC categories."""
        current_iocs = cls._extract_iocs(current_incident)
        historical_iocs = cls._extract_iocs(historical_incident)

        shared_iocs: dict[str, list[str]] = {}
        current_flat: set[str] = set()
        historical_flat: set[str] = set()

        all_ioc_types = set(current_iocs) | set(historical_iocs)

        for ioc_type in sorted(all_ioc_types):
            current_values = current_iocs.get(ioc_type, set())
            historical_values = historical_iocs.get(ioc_type, set())

            current_flat.update(
                f"{ioc_type}:{value}" for value in current_values
            )
            historical_flat.update(
                f"{ioc_type}:{value}" for value in historical_values
            )

            overlap = current_values & historical_values

            if overlap:
                shared_iocs[ioc_type] = sorted(overlap)

        similarity = cls._jaccard_similarity(
            current_flat,
            historical_flat,
        )

        shared_count = sum(
            len(values)
            for values in shared_iocs.values()
        )

        return {
            "shared": shared_iocs,
            "shared_count": shared_count,
            "similarity": similarity,
        }

    @classmethod
    def _compare_mitre(
        cls,
        current_incident: dict[str, Any],
        historical_incident: dict[str, Any],
    ) -> dict[str, Any]:
        """Compare MITRE ATT&CK techniques."""
        current_mitre = cls._extract_mitre(current_incident)
        historical_mitre = cls._extract_mitre(historical_incident)

        shared = current_mitre & historical_mitre

        return {
            "shared": sorted(shared),
            "shared_count": len(shared),
            "similarity": cls._jaccard_similarity(
                current_mitre,
                historical_mitre,
            ),
        }

    @classmethod
    def _compare_detections(
        cls,
        current_incident: dict[str, Any],
        historical_incident: dict[str, Any],
    ) -> dict[str, Any]:
        """Compare normalized detection names."""
        current_detections = cls._extract_detections(current_incident)
        historical_detections = cls._extract_detections(
            historical_incident
        )

        shared = current_detections & historical_detections

        return {
            "shared": sorted(shared),
            "shared_count": len(shared),
            "similarity": cls._jaccard_similarity(
                current_detections,
                historical_detections,
            ),
        }

    @classmethod
    def _calculate_similarity_score(
        cls,
        ioc_similarity: float,
        mitre_similarity: float,
        detection_similarity: float,
    ) -> float:
        """
        Calculate a weighted similarity score from 0 to 100.

        Weights:
        - IOC overlap: 50%
        - MITRE overlap: 30%
        - Detection overlap: 20%
        """
        score = (
            ioc_similarity * cls.IOC_WEIGHT
            + mitre_similarity * cls.MITRE_WEIGHT
            + detection_similarity * cls.DETECTION_WEIGHT
        ) * 100

        return round(min(max(score, 0.0), 100.0), 2)

    @staticmethod
    def _determine_match_level(score: float) -> str:
        """Convert a numeric similarity score into a stable label."""
        if score >= 75:
            return "VERY_HIGH"

        if score >= 50:
            return "HIGH"

        if score >= 25:
            return "MEDIUM"

        if score > 0:
            return "LOW"

        return "NONE"

    @staticmethod
    def _build_evidence(
        ioc_result: dict[str, Any],
        mitre_result: dict[str, Any],
        detection_result: dict[str, Any],
    ) -> list[str]:
        """Build deterministic human-readable correlation evidence."""
        evidence: list[str] = []

        if ioc_result["shared_count"] > 0:
            evidence.append(
                f"{ioc_result['shared_count']} shared IOC value(s)"
            )

        if mitre_result["shared_count"] > 0:
            evidence.append(
                f"{mitre_result['shared_count']} shared MITRE technique(s)"
            )

        if detection_result["shared_count"] > 0:
            evidence.append(
                f"{detection_result['shared_count']} shared detection(s)"
            )

        return evidence

    def compare_incidents(
        self,
        current_incident: dict[str, Any],
        historical_incident: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Compare one current incident with one historical incident.
        """
        self._validate_incident(current_incident)
        self._validate_incident(historical_incident)

        ioc_result = self._compare_iocs(
            current_incident,
            historical_incident,
        )

        mitre_result = self._compare_mitre(
            current_incident,
            historical_incident,
        )

        detection_result = self._compare_detections(
            current_incident,
            historical_incident,
        )

        similarity_score = self._calculate_similarity_score(
            ioc_similarity=ioc_result["similarity"],
            mitre_similarity=mitre_result["similarity"],
            detection_similarity=detection_result["similarity"],
        )

        return {
            "incident_id": historical_incident.get("incident_id"),
            "timestamp": historical_incident.get("timestamp"),
            "similarity_score": similarity_score,
            "match_level": self._determine_match_level(
                similarity_score
            ),
            "shared_iocs": ioc_result["shared"],
            "shared_ioc_count": ioc_result["shared_count"],
            "shared_mitre": mitre_result["shared"],
            "shared_mitre_count": mitre_result["shared_count"],
            "shared_detections": detection_result["shared"],
            "shared_detection_count": detection_result[
                "shared_count"
            ],
            "evidence": self._build_evidence(
                ioc_result,
                mitre_result,
                detection_result,
            ),
        }

    def correlate_incident(
        self,
        current_incident: dict[str, Any],
        *,
        minimum_score: float = DEFAULT_MINIMUM_SCORE,
        maximum_results: int | None = 10,
    ) -> dict[str, Any]:
        """
        Compare a current incident with all stored historical incidents.

        The current incident is not saved automatically.

        Results are sorted by:
        1. Highest similarity score
        2. Highest shared IOC count
        3. Highest shared MITRE count
        4. Incident ID
        """
        self._validate_incident(current_incident)

        if isinstance(minimum_score, bool) or not isinstance(
            minimum_score,
            (int, float),
        ):
            raise InvalidCorrelationInputError(
                "'minimum_score' must be numeric."
            )

        if not 0 <= minimum_score <= 100:
            raise InvalidCorrelationInputError(
                "'minimum_score' must be between 0 and 100."
            )

        if maximum_results is not None:
            if (
                isinstance(maximum_results, bool)
                or not isinstance(maximum_results, int)
                or maximum_results < 1
            ):
                raise InvalidCorrelationInputError(
                    "'maximum_results' must be a positive integer or None."
                )

        current_incident_id = current_incident.get("incident_id")
        historical_incidents = (
            self.incident_store.get_all_incidents()
        )

        matches: list[dict[str, Any]] = []

        for historical_incident in historical_incidents:
            historical_incident_id = historical_incident.get(
                "incident_id"
            )

            if (
                current_incident_id is not None
                and current_incident_id == historical_incident_id
            ):
                continue

            result = self.compare_incidents(
                current_incident,
                historical_incident,
            )

            if result["similarity_score"] >= minimum_score:
                matches.append(result)

        matches.sort(
            key=lambda match: (
                -match["similarity_score"],
                -match["shared_ioc_count"],
                -match["shared_mitre_count"],
                str(match.get("incident_id", "")),
            )
        )

        if maximum_results is not None:
            matches = matches[:maximum_results]

        highest_score = (
            matches[0]["similarity_score"]
            if matches
            else 0.0
        )

        return {
            "historical_incidents_checked": len(
                historical_incidents
            ),
            "matching_incidents_found": len(matches),
            "highest_similarity_score": highest_score,
            "has_historical_match": bool(matches),
            "matches": deepcopy(matches),
        }

    def find_ioc_occurrences(
        self,
        ioc_value: str,
        *,
        ioc_type: str | None = None,
    ) -> dict[str, Any]:
        """
        Find every stored occurrence of a specific IOC.

        When ioc_type is provided, only that IOC category is searched.
        """
        normalized_value = self._normalize_string(ioc_value)

        if normalized_value is None:
            raise InvalidCorrelationInputError(
                "'ioc_value' must be a non-empty string."
            )

        normalized_type = self._normalize_string(ioc_type)

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

            if matched_types:
                occurrences.append(
                    {
                        "incident_id": incident.get("incident_id"),
                        "timestamp": incident.get("timestamp"),
                        "ioc_types": sorted(matched_types),
                        "risk_score": incident.get("risk_score"),
                        "severity": incident.get("severity"),
                    }
                )

        occurrences.sort(
            key=lambda occurrence: (
                str(occurrence.get("timestamp", "")),
                str(occurrence.get("incident_id", "")),
            )
        )

        return {
            "ioc": normalized_value,
            "ioc_type_filter": normalized_type,
            "occurrence_count": len(occurrences),
            "is_repeat_offender": len(occurrences) > 1,
            "first_seen": (
                occurrences[0].get("timestamp")
                if occurrences
                else None
            ),
            "last_seen": (
                occurrences[-1].get("timestamp")
                if occurrences
                else None
            ),
            "occurrences": occurrences,
        }