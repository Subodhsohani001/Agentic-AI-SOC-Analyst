"""
Deterministic threat-intelligence summary builder.

This module converts verified enrichment, reputation, and correlation
results into a compact analyst-ready structure.

It performs no network requests and uses no LLM reasoning.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class IntelligenceSummaryBuilder:
    """Build a stable threat-intelligence summary from verified evidence."""

    def build(
        self,
        ioc: str,
        reputation: dict[str, Any],
        correlation: dict[str, Any] | None = None,
        virustotal: dict[str, Any] | None = None,
        abuseipdb: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Build an analyst-ready threat-intelligence summary.

        Args:
            ioc:
                Observable being summarized.

            reputation:
                Output from ReputationEngine.evaluate().

            correlation:
                Optional output from IntelligenceCorrelator.correlate().

            virustotal:
                Optional normalized VirusTotal response.

            abuseipdb:
                Optional normalized AbuseIPDB response.

        Returns:
            Stable summary containing verdict, risk, evidence,
            provider findings, correlation findings, and analyst guidance.
        """
        normalized_ioc = self._normalize_ioc(ioc)

        if not isinstance(reputation, dict):
            raise TypeError("reputation must be a dictionary.")

        correlation_data = (
            correlation
            if isinstance(correlation, dict)
            else {}
        )

        vt_summary = self._summarize_virustotal(virustotal)
        abuse_summary = self._summarize_abuseipdb(abuseipdb)
        correlation_summary = self._summarize_correlation(
            correlation_data
        )

        risk_score = self._clamp_score(
            reputation.get("risk_score")
        )

        verdict = self._safe_string(
            reputation.get("verdict")
        ) or "unknown"

        severity = self._safe_string(
            reputation.get("severity")
        ) or "UNKNOWN"

        confidence = self._safe_string(
            reputation.get("confidence")
        ) or "Low"

        recommended_action = self._safe_string(
            correlation_data.get(
                "recommended_action",
                reputation.get("recommended_action"),
            )
        ) or "manual_review"

        evidence = self._merge_evidence(
            reputation=reputation,
            correlation=correlation_data,
        )

        contradictions = self._safe_string_list(
            reputation.get("contradictions")
        )

        executive_summary = self._build_executive_summary(
            ioc=normalized_ioc,
            risk_score=risk_score,
            verdict=verdict,
            severity=severity,
            confidence=confidence,
            correlation=correlation_summary,
            provider_findings={
                "virustotal": vt_summary,
                "abuseipdb": abuse_summary,
            },
        )

        analyst_notes = self._build_analyst_notes(
            risk_score=risk_score,
            confidence=confidence,
            contradictions=contradictions,
            correlation=correlation_summary,
            virustotal=vt_summary,
            abuseipdb=abuse_summary,
        )

        return {
            "ioc": normalized_ioc,
            "risk_score": risk_score,
            "verdict": verdict,
            "severity": severity,
            "confidence": confidence,
            "recommended_action": recommended_action,
            "executive_summary": executive_summary,
            "provider_findings": {
                "virustotal": vt_summary,
                "abuseipdb": abuse_summary,
            },
            "correlation": correlation_summary,
            "evidence": evidence,
            "contradictions": contradictions,
            "analyst_notes": analyst_notes,
            "generated_at": datetime.now(timezone.utc).isoformat(),
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

    def _summarize_virustotal(
        self,
        data: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Create a compact VirusTotal summary."""
        if not isinstance(data, dict):
            return {
                "available": False,
                "status": "not_available",
            }

        stats = data.get("analysis_stats", {})

        if not isinstance(stats, dict):
            stats = {}

        malicious = self._safe_int(stats.get("malicious"))
        suspicious = self._safe_int(stats.get("suspicious"))
        harmless = self._safe_int(stats.get("harmless"))
        undetected = self._safe_int(stats.get("undetected"))
        total_engines = self._safe_int(
            data.get("total_engines")
        )

        if total_engines <= 0:
            total_engines = (
                malicious
                + suspicious
                + harmless
                + undetected
                + self._safe_int(stats.get("timeout"))
            )

        detection_ratio = self._safe_float(
            data.get("detection_ratio_percent")
        )

        if detection_ratio == 0.0 and total_engines > 0:
            detection_ratio = round(
                (
                    (malicious + suspicious)
                    / total_engines
                )
                * 100,
                2,
            )

        return {
            "available": True,
            "status": "available",
            "verdict": self._safe_string(data.get("verdict")),
            "malicious_engines": malicious,
            "suspicious_engines": suspicious,
            "harmless_engines": harmless,
            "undetected_engines": undetected,
            "total_engines": total_engines,
            "detection_ratio_percent": round(
                detection_ratio,
                2,
            ),
            "reputation": self._safe_int(
                data.get("reputation")
            ),
            "tags": self._safe_string_list(data.get("tags")),
            "cache_hit": bool(data.get("cache_hit", False)),
        }

    def _summarize_abuseipdb(
        self,
        data: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Create a compact AbuseIPDB summary."""
        if not isinstance(data, dict):
            return {
                "available": False,
                "status": "not_available",
            }

        return {
            "available": True,
            "status": "available",
            "verdict": self._safe_string(data.get("verdict")),
            "abuse_confidence_score": self._clamp_score(
                data.get("abuse_confidence_score")
            ),
            "is_whitelisted": (
                data.get("is_whitelisted")
                if isinstance(
                    data.get("is_whitelisted"),
                    bool,
                )
                else None
            ),
            "total_reports": self._safe_int(
                data.get("total_reports")
            ),
            "num_distinct_users": self._safe_int(
                data.get("num_distinct_users")
            ),
            "country_code": self._safe_string(
                data.get("country_code")
            ),
            "isp": self._safe_string(data.get("isp")),
            "usage_type": self._safe_string(
                data.get("usage_type")
            ),
            "domain": self._safe_string(data.get("domain")),
            "hostnames": self._safe_string_list(
                data.get("hostnames")
            ),
            "last_reported_at": self._safe_string(
                data.get("last_reported_at")
            ),
            "cache_hit": bool(data.get("cache_hit", False)),
        }

    def _summarize_correlation(
        self,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a compact correlation summary."""
        if not data:
            return {
                "available": False,
                "status": "not_available",
            }

        return {
            "available": True,
            "status": "available",
            "correlation_score": self._clamp_score(
                data.get("correlation_score")
            ),
            "match_level": self._safe_string(
                data.get("match_level")
            ),
            "investigation_priority": self._safe_string(
                data.get("investigation_priority")
            ),
            "occurrence_count": self._safe_int(
                data.get("occurrence_count")
            ),
            "is_repeat_offender": bool(
                data.get("is_repeat_offender", False)
            ),
            "first_seen": self._safe_string(
                data.get("first_seen")
            ),
            "last_seen": self._safe_string(
                data.get("last_seen")
            ),
            "risk_trend": self._safe_string(
                data.get("risk_trend")
            ),
            "provider_agreement": self._safe_string(
                data.get("provider_agreement")
            ),
            "shared_mitre_techniques": (
                self._safe_string_list(
                    data.get("shared_mitre_techniques")
                )
            ),
            "shared_detection_patterns": (
                self._safe_string_list(
                    data.get("shared_detection_patterns")
                )
            ),
            "historical_incident_ids": (
                self._safe_string_list(
                    data.get("historical_incident_ids")
                )
            ),
        }

    def _merge_evidence(
        self,
        reputation: dict[str, Any],
        correlation: dict[str, Any],
    ) -> list[str]:
        """Merge and deduplicate verified evidence."""
        reputation_evidence = self._safe_string_list(
            reputation.get("evidence")
        )

        correlation_evidence = self._safe_string_list(
            correlation.get("evidence")
        )

        return list(
            dict.fromkeys(
                reputation_evidence + correlation_evidence
            )
        )

    def _build_executive_summary(
        self,
        ioc: str,
        risk_score: int,
        verdict: str,
        severity: str,
        confidence: str,
        correlation: dict[str, Any],
        provider_findings: dict[str, dict[str, Any]],
    ) -> str:
        """Build a deterministic executive summary."""
        parts = [
            (
                f"IOC {ioc} received a risk score of "
                f"{risk_score}/100 and was classified as "
                f"{verdict} with {severity} severity."
            ),
            f"Assessment confidence is {confidence}.",
        ]

        if correlation.get("available"):
            if correlation.get("is_repeat_offender"):
                parts.append(
                    "The IOC is a repeat offender in local "
                    "incident history."
                )

            match_level = correlation.get("match_level")

            if match_level:
                parts.append(
                    f"Historical correlation level is "
                    f"{match_level}."
                )

            risk_trend = correlation.get("risk_trend")

            if risk_trend and risk_trend != "new":
                parts.append(
                    f"Historical risk trend is {risk_trend}."
                )

        vt_data = provider_findings["virustotal"]
        abuse_data = provider_findings["abuseipdb"]

        if (
            vt_data.get("available")
            and abuse_data.get("available")
        ):
            parts.append(
                "The assessment includes evidence from "
                "VirusTotal and AbuseIPDB."
            )

        elif vt_data.get("available"):
            parts.append(
                "The assessment includes VirusTotal evidence only."
            )

        elif abuse_data.get("available"):
            parts.append(
                "The assessment includes AbuseIPDB evidence only."
            )

        else:
            parts.append(
                "No external threat-intelligence provider evidence "
                "was available."
            )

        return " ".join(parts)

    def _build_analyst_notes(
        self,
        risk_score: int,
        confidence: str,
        contradictions: list[str],
        correlation: dict[str, Any],
        virustotal: dict[str, Any],
        abuseipdb: dict[str, Any],
    ) -> list[str]:
        """Build deterministic analyst guidance."""
        notes: list[str] = []

        if contradictions:
            notes.append(
                "Review provider contradictions before taking "
                "automated containment action."
            )

        if confidence == "Low":
            notes.append(
                "Assessment confidence is low; gather additional "
                "telemetry before escalation."
            )

        if correlation.get("is_repeat_offender"):
            notes.append(
                "Review all historical incidents associated with "
                "this IOC."
            )

        if correlation.get("risk_trend") == "increasing":
            notes.append(
                "The IOC risk trend is increasing and should be "
                "prioritized for investigation."
            )

        if (
            abuseipdb.get("is_whitelisted") is True
            and risk_score >= 40
        ):
            notes.append(
                "The IP is externally whitelisted but current "
                "evidence indicates elevated risk."
            )

        if (
            virustotal.get("malicious_engines", 0) >= 10
            and abuseipdb.get("abuse_confidence_score", 0) >= 70
        ):
            notes.append(
                "Multiple independent providers strongly support "
                "a malicious classification."
            )

        if risk_score < 16 and not notes:
            notes.append(
                "No immediate containment is required; retain "
                "the event for monitoring and future correlation."
            )

        if not notes:
            notes.append(
                "Proceed according to the recommended response action."
            )

        return notes

    @staticmethod
    def _safe_int(value: Any) -> int:
        """Convert a value to int, returning zero on failure."""
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _safe_float(value: Any) -> float:
        """Convert a value to float, returning zero on failure."""
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    @classmethod
    def _clamp_score(cls, value: Any) -> int:
        """Clamp a numeric score to the range 0–100."""
        return max(0, min(cls._safe_int(value), 100))

    @staticmethod
    def _safe_string(value: Any) -> str | None:
        """Return a cleaned string or None."""
        if not isinstance(value, str):
            return None

        cleaned = value.strip()
        return cleaned or None

    @staticmethod
    def _safe_string_list(value: Any) -> list[str]:
        """Return a clean list of non-empty strings."""
        if not isinstance(value, list):
            return []

        return [
            item.strip()
            for item in value
            if isinstance(item, str) and item.strip()
        ]