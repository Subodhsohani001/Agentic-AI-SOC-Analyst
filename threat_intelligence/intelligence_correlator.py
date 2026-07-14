"""
Deterministic threat-intelligence correlation engine.

This module correlates:
- Final IOC reputation assessment
- VirusTotal and AbuseIPDB evidence
- Historical incident memory
- Current incident context
- MITRE ATT&CK techniques
- Detection overlap
- Risk-score trends

It performs no network requests and uses no LLM reasoning.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class IntelligenceCorrelator:
    """Correlate verified IOC intelligence with incident history."""

    def correlate(
        self,
        ioc: str,
        reputation: dict[str, Any],
        history: dict[str, Any] | None = None,
        current_incident: dict[str, Any] | None = None,
        virustotal: dict[str, Any] | None = None,
        abuseipdb: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Build an evidence-based IOC correlation result.

        Args:
            ioc:
                Observable being investigated.

            reputation:
                Output from ReputationEngine.evaluate().

            history:
                IOC history or historical incident data.

            current_incident:
                Current incident, alert, or investigation context.

            virustotal:
                Optional normalized VirusTotal result.

            abuseipdb:
                Optional normalized AbuseIPDB result.

        Returns:
            Stable deterministic correlation result.
        """
        normalized_ioc = self._normalize_ioc(ioc)

        if not isinstance(reputation, dict):
            raise TypeError("reputation must be a dictionary.")

        history_data = history if isinstance(history, dict) else {}
        incident_data = (
            current_incident
            if isinstance(current_incident, dict)
            else {}
        )

        historical_incidents = self._extract_historical_incidents(
            history_data
        )

        occurrence_count = self._derive_occurrence_count(
            history=history_data,
            incidents=historical_incidents,
        )

        is_repeat_offender = bool(
            history_data.get(
                "is_repeat_offender",
                occurrence_count >= 2,
            )
        )

        first_seen = self._derive_first_seen(
            history=history_data,
            incidents=historical_incidents,
        )

        last_seen = self._derive_last_seen(
            history=history_data,
            incidents=historical_incidents,
        )

        current_mitre = self._extract_mitre_ids(incident_data)
        historical_mitre = self._collect_historical_mitre(
            historical_incidents
        )
        shared_mitre = sorted(current_mitre & historical_mitre)

        current_detections = self._extract_detections(incident_data)
        historical_detections = self._collect_historical_detections(
            historical_incidents
        )
        shared_detections = sorted(
            current_detections & historical_detections
        )

        current_risk = self._clamp_score(
            reputation.get(
                "risk_score",
                incident_data.get("risk_score", 0),
            )
        )

        historical_risks = self._collect_historical_risks(
            history=history_data,
            incidents=historical_incidents,
        )

        risk_trend = self._derive_risk_trend(
            current_risk=current_risk,
            historical_risks=historical_risks,
        )

        provider_agreement = self._derive_provider_agreement(
            virustotal=virustotal,
            abuseipdb=abuseipdb,
            reputation=reputation,
        )

        correlation_score = self._calculate_correlation_score(
            occurrence_count=occurrence_count,
            is_repeat_offender=is_repeat_offender,
            shared_mitre_count=len(shared_mitre),
            shared_detection_count=len(shared_detections),
            risk_trend=risk_trend,
            current_risk=current_risk,
            provider_agreement=provider_agreement,
        )

        match_level = self._derive_match_level(correlation_score)

        evidence = self._build_evidence(
            occurrence_count=occurrence_count,
            is_repeat_offender=is_repeat_offender,
            shared_mitre=shared_mitre,
            shared_detections=shared_detections,
            first_seen=first_seen,
            last_seen=last_seen,
            risk_trend=risk_trend,
            provider_agreement=provider_agreement,
        )

        investigation_priority = self._derive_priority(
            current_risk=current_risk,
            correlation_score=correlation_score,
            is_repeat_offender=is_repeat_offender,
            risk_trend=risk_trend,
        )

        recommended_action = self._derive_action(
            investigation_priority=investigation_priority,
            current_risk=current_risk,
            is_repeat_offender=is_repeat_offender,
        )

        return {
            "ioc": normalized_ioc,
            "correlation_score": correlation_score,
            "match_level": match_level,
            "investigation_priority": investigation_priority,
            "recommended_action": recommended_action,
            "occurrence_count": occurrence_count,
            "is_repeat_offender": is_repeat_offender,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "historical_incident_count": len(historical_incidents),
            "historical_incident_ids": self._collect_incident_ids(
                historical_incidents
            ),
            "current_risk_score": current_risk,
            "highest_historical_risk_score": (
                max(historical_risks)
                if historical_risks
                else 0
            ),
            "risk_trend": risk_trend,
            "shared_mitre_techniques": shared_mitre,
            "shared_detection_patterns": shared_detections,
            "provider_agreement": provider_agreement,
            "evidence": evidence,
            "correlated_at": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _normalize_ioc(ioc: str) -> str:
        """Validate and normalize an IOC."""
        if not isinstance(ioc, str):
            raise TypeError("IOC must be a string.")

        normalized = ioc.strip().lower()

        if not normalized:
            raise ValueError("IOC cannot be empty.")

        return normalized

    @staticmethod
    def _extract_historical_incidents(
        history: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Extract historical incident dictionaries."""
        possible_keys = (
            "incidents",
            "historical_incidents",
            "matching_incidents",
            "related_incidents",
        )

        for key in possible_keys:
            value = history.get(key)

            if isinstance(value, list):
                return [
                    incident
                    for incident in value
                    if isinstance(incident, dict)
                ]

        return []

    def _derive_occurrence_count(
        self,
        history: dict[str, Any],
        incidents: list[dict[str, Any]],
    ) -> int:
        """Derive the number of historical IOC occurrences."""
        explicit_count = self._safe_int(
            history.get(
                "occurrence_count",
                history.get("historical_incident_count", 0),
            )
        )

        return max(explicit_count, len(incidents))

    def _derive_first_seen(
        self,
        history: dict[str, Any],
        incidents: list[dict[str, Any]],
    ) -> str | None:
        """Return the earliest verified IOC timestamp."""
        explicit = self._safe_string(history.get("first_seen"))

        if explicit:
            return explicit

        timestamps = self._collect_timestamps(incidents)

        return min(timestamps) if timestamps else None

    def _derive_last_seen(
        self,
        history: dict[str, Any],
        incidents: list[dict[str, Any]],
    ) -> str | None:
        """Return the latest verified IOC timestamp."""
        explicit = self._safe_string(history.get("last_seen"))

        if explicit:
            return explicit

        timestamps = self._collect_timestamps(incidents)

        return max(timestamps) if timestamps else None

    def _collect_timestamps(
        self,
        incidents: list[dict[str, Any]],
    ) -> list[str]:
        """Collect parseable incident timestamps."""
        collected: list[tuple[datetime, str]] = []

        for incident in incidents:
            raw_timestamp = self._safe_string(
                incident.get(
                    "timestamp",
                    incident.get(
                        "created_at",
                        incident.get("detected_at"),
                    ),
                )
            )

            if not raw_timestamp:
                continue

            parsed = self._parse_datetime(raw_timestamp)

            if parsed is not None:
                collected.append((parsed, raw_timestamp))

        return [
            raw
            for _, raw in sorted(collected, key=lambda item: item[0])
        ]

    @staticmethod
    def _parse_datetime(value: str) -> datetime | None:
        """Parse an ISO-8601 timestamp safely."""
        normalized = value.strip().replace("Z", "+00:00")

        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed

    def _extract_mitre_ids(
        self,
        incident: dict[str, Any],
    ) -> set[str]:
        """Extract MITRE ATT&CK IDs from one incident."""
        values: list[Any] = []

        for key in (
            "mitre_ids",
            "mitre_techniques",
            "mitre_attack",
            "mitre",
        ):
            value = incident.get(key)

            if value is not None:
                values.append(value)

        extracted: set[str] = set()

        for value in values:
            extracted.update(self._normalize_mitre_value(value))

        return extracted

    def _normalize_mitre_value(self, value: Any) -> set[str]:
        """Normalize flexible MITRE structures into technique IDs."""
        results: set[str] = set()

        if isinstance(value, str):
            cleaned = value.strip().upper()

            if cleaned.startswith("T"):
                results.add(cleaned)

        elif isinstance(value, dict):
            technique_id = value.get("id")

            if isinstance(technique_id, str):
                cleaned = technique_id.strip().upper()

                if cleaned.startswith("T"):
                    results.add(cleaned)

            for nested_value in value.values():
                if isinstance(nested_value, (list, dict)):
                    results.update(
                        self._normalize_mitre_value(nested_value)
                    )

        elif isinstance(value, list):
            for item in value:
                results.update(self._normalize_mitre_value(item))

        return results

    def _collect_historical_mitre(
        self,
        incidents: list[dict[str, Any]],
    ) -> set[str]:
        """Collect MITRE IDs across historical incidents."""
        collected: set[str] = set()

        for incident in incidents:
            collected.update(self._extract_mitre_ids(incident))

        return collected

    def _extract_detections(
        self,
        incident: dict[str, Any],
    ) -> set[str]:
        """Extract normalized detection names from an incident."""
        raw_detections = incident.get(
            "detections",
            incident.get(
                "detection_patterns",
                incident.get("matched_rules", []),
            ),
        )

        if isinstance(raw_detections, str):
            raw_detections = [raw_detections]

        if not isinstance(raw_detections, list):
            return set()

        return {
            detection.strip().lower()
            for detection in raw_detections
            if isinstance(detection, str) and detection.strip()
        }

    def _collect_historical_detections(
        self,
        incidents: list[dict[str, Any]],
    ) -> set[str]:
        """Collect detection patterns from historical incidents."""
        collected: set[str] = set()

        for incident in incidents:
            collected.update(self._extract_detections(incident))

        return collected

    def _collect_historical_risks(
        self,
        history: dict[str, Any],
        incidents: list[dict[str, Any]],
    ) -> list[int]:
        """Collect valid historical risk scores."""
        risks: list[int] = []

        explicit_max = self._safe_int(
            history.get(
                "highest_historical_risk_score",
                history.get("max_risk_score", 0),
            )
        )

        if explicit_max > 0:
            risks.append(self._clamp_score(explicit_max))

        for incident in incidents:
            raw_score = incident.get(
                "risk_score",
                incident.get("combined_risk_score", 0),
            )

            score = self._clamp_score(raw_score)

            if score > 0:
                risks.append(score)

        return risks

    @staticmethod
    def _collect_incident_ids(
        incidents: list[dict[str, Any]],
    ) -> list[str]:
        """Collect unique historical incident identifiers."""
        incident_ids: list[str] = []

        for incident in incidents:
            incident_id = incident.get(
                "incident_id",
                incident.get("id"),
            )

            if isinstance(incident_id, str) and incident_id.strip():
                incident_ids.append(incident_id.strip())

        return list(dict.fromkeys(incident_ids))

    @staticmethod
    def _derive_risk_trend(
        current_risk: int,
        historical_risks: list[int],
    ) -> str:
        """Compare current risk against historical risk."""
        if not historical_risks:
            return "new"

        previous_highest = max(historical_risks)
        difference = current_risk - previous_highest

        if difference >= 15:
            return "increasing"

        if difference <= -15:
            return "decreasing"

        return "stable"

    def _derive_provider_agreement(
        self,
        virustotal: dict[str, Any] | None,
        abuseipdb: dict[str, Any] | None,
        reputation: dict[str, Any],
    ) -> str:
        """Determine whether intelligence providers agree."""
        if not isinstance(virustotal, dict) or not isinstance(
            abuseipdb,
            dict,
        ):
            return "insufficient_data"

        vt_stats = virustotal.get("analysis_stats", {})

        malicious = (
            self._safe_int(vt_stats.get("malicious"))
            if isinstance(vt_stats, dict)
            else 0
        )

        abuse_score = self._clamp_score(
            abuseipdb.get("abuse_confidence_score")
        )

        whitelisted = abuseipdb.get("is_whitelisted") is True
        final_score = self._clamp_score(reputation.get("risk_score"))

        vt_malicious = malicious >= 3
        abuse_malicious = abuse_score >= 70

        if vt_malicious and abuse_malicious:
            return "malicious_agreement"

        if (
            malicious <= 1
            and abuse_score < 25
            and final_score < 40
        ):
            return "benign_agreement"

        if whitelisted and vt_malicious:
            return "conflicting"

        if vt_malicious != abuse_malicious:
            return "partial_disagreement"

        return "inconclusive"

    @staticmethod
    def _calculate_correlation_score(
        occurrence_count: int,
        is_repeat_offender: bool,
        shared_mitre_count: int,
        shared_detection_count: int,
        risk_trend: str,
        current_risk: int,
        provider_agreement: str,
    ) -> int:
        """Calculate deterministic correlation strength."""
        score = 0.0

        score += min(occurrence_count * 8, 32)

        if is_repeat_offender:
            score += 18

        score += min(shared_mitre_count * 10, 20)
        score += min(shared_detection_count * 8, 16)

        if risk_trend == "increasing":
            score += 10

        elif risk_trend == "stable" and occurrence_count > 0:
            score += 4

        if current_risk >= 85:
            score += 8

        elif current_risk >= 65:
            score += 5

        if provider_agreement == "malicious_agreement":
            score += 10

        elif provider_agreement == "conflicting":
            score += 3

        return int(round(min(score, 100.0)))

    @staticmethod
    def _derive_match_level(score: int) -> str:
        """Map correlation score to a match level."""
        if score >= 75:
            return "CRITICAL"

        if score >= 50:
            return "HIGH"

        if score >= 25:
            return "MEDIUM"

        if score > 0:
            return "LOW"

        return "NONE"

    @staticmethod
    def _derive_priority(
        current_risk: int,
        correlation_score: int,
        is_repeat_offender: bool,
        risk_trend: str,
    ) -> str:
        """Derive analyst investigation priority."""
        if (
            current_risk >= 85
            or correlation_score >= 75
            or (
                is_repeat_offender
                and risk_trend == "increasing"
            )
        ):
            return "P1"

        if current_risk >= 65 or correlation_score >= 50:
            return "P2"

        if current_risk >= 40 or correlation_score >= 25:
            return "P3"

        return "P4"

    @staticmethod
    def _derive_action(
        investigation_priority: str,
        current_risk: int,
        is_repeat_offender: bool,
    ) -> str:
        """Return a deterministic investigation action."""
        if investigation_priority == "P1":
            return "escalate_and_contain"

        if investigation_priority == "P2":
            return "open_priority_investigation"

        if investigation_priority == "P3":
            return "create_ticket_and_review"

        if is_repeat_offender or current_risk >= 16:
            return "monitor_and_correlate"

        return "record_and_close"

    @staticmethod
    def _build_evidence(
        occurrence_count: int,
        is_repeat_offender: bool,
        shared_mitre: list[str],
        shared_detections: list[str],
        first_seen: str | None,
        last_seen: str | None,
        risk_trend: str,
        provider_agreement: str,
    ) -> list[str]:
        """Build human-readable evidence from verified facts."""
        evidence: list[str] = []

        if occurrence_count > 0:
            evidence.append(
                f"IOC appeared in {occurrence_count} historical "
                f"incident(s)."
            )

        if is_repeat_offender:
            evidence.append(
                "IOC is classified as a repeat offender."
            )

        if shared_mitre:
            evidence.append(
                "Shared MITRE techniques: "
                + ", ".join(shared_mitre)
                + "."
            )

        if shared_detections:
            evidence.append(
                "Shared detection patterns: "
                + ", ".join(shared_detections)
                + "."
            )

        if first_seen:
            evidence.append(f"First seen: {first_seen}.")

        if last_seen:
            evidence.append(f"Last seen: {last_seen}.")

        if risk_trend != "new":
            evidence.append(
                f"Historical risk trend is {risk_trend}."
            )

        if provider_agreement not in {
            "insufficient_data",
            "inconclusive",
        }:
            evidence.append(
                "Threat-intelligence provider relationship: "
                f"{provider_agreement}."
            )

        return evidence

    @staticmethod
    def _safe_int(value: Any) -> int:
        """Convert a value to int, returning zero on failure."""
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    @classmethod
    def _clamp_score(cls, value: Any) -> int:
        """Clamp a numeric value to the range 0–100."""
        return max(0, min(cls._safe_int(value), 100))

    @staticmethod
    def _safe_string(value: Any) -> str | None:
        """Return a cleaned string or None."""
        if not isinstance(value, str):
            return None

        cleaned = value.strip()
        return cleaned or None