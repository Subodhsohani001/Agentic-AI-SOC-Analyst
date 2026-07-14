"""
Deterministic multi-source IOC reputation engine.

Evidence sources:
- VirusTotal
- AbuseIPDB
- Historical incident memory
- Current local detection evidence

This module performs no network requests and uses no LLM reasoning.
"""

from __future__ import annotations

from typing import Any


class ReputationEngine:
    """Fuse verified intelligence into one deterministic risk assessment."""

    SOURCE_WEIGHTS = {
        "virustotal": 0.45,
        "abuseipdb": 0.35,
        "history": 0.12,
        "local_evidence": 0.08,
    }

    def evaluate(
        self,
        ioc: str,
        virustotal: dict[str, Any] | None = None,
        abuseipdb: dict[str, Any] | None = None,
        history: dict[str, Any] | None = None,
        local_evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Produce a deterministic reputation assessment.

        Args:
            ioc:
                Observable being evaluated.

            virustotal:
                Normalized output from VirusTotalClient.lookup().

            abuseipdb:
                Normalized output from AbuseIPDBClient.lookup().

            history:
                Historical evidence from incident memory.

            local_evidence:
                Evidence from the currently analyzed log or alert.

        Returns:
            Stable reputation result containing score, verdict,
            confidence, evidence, and contradictions.
        """
        normalized_ioc = self._normalize_ioc(ioc)

        components: dict[str, dict[str, Any]] = {}
        evidence: list[str] = []
        contradictions: list[str] = []

        if isinstance(virustotal, dict):
            vt_component = self._score_virustotal(virustotal)
            components["virustotal"] = vt_component
            evidence.extend(vt_component["evidence"])

        if isinstance(abuseipdb, dict):
            abuse_component = self._score_abuseipdb(abuseipdb)
            components["abuseipdb"] = abuse_component
            evidence.extend(abuse_component["evidence"])

        if isinstance(history, dict):
            history_component = self._score_history(history)
            components["history"] = history_component
            evidence.extend(history_component["evidence"])

        if isinstance(local_evidence, dict):
            local_component = self._score_local_evidence(local_evidence)
            components["local_evidence"] = local_component
            evidence.extend(local_component["evidence"])

        weighted_score = self._combine_components(components)

        contradictions.extend(
            self._detect_contradictions(
                virustotal=virustotal,
                abuseipdb=abuseipdb,
                history=history,
            )
        )

        adjusted_score = self._apply_contextual_adjustments(
            score=weighted_score,
            virustotal=virustotal,
            abuseipdb=abuseipdb,
            history=history,
            local_evidence=local_evidence,
        )

        confidence = self._derive_confidence(
            components=components,
            contradictions=contradictions,
        )

        verdict = self._derive_verdict(adjusted_score)
        severity = self._derive_severity(adjusted_score)

        return {
            "ioc": normalized_ioc,
            "risk_score": adjusted_score,
            "verdict": verdict,
            "severity": severity,
            "confidence": confidence,
            "provider_count": self._provider_count(
                virustotal=virustotal,
                abuseipdb=abuseipdb,
            ),
            "evidence_source_count": sum(
                bool(component.get("evidence"))
                for component in components.values()
            ),
            "components": components,
            "evidence": self._deduplicate_strings(evidence),
            "contradictions": self._deduplicate_strings(contradictions),
            "recommended_action": self._recommended_action(
                score=adjusted_score,
                confidence=confidence,
            ),
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

    def _score_virustotal(
        self,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Calculate a VirusTotal risk component from verified fields."""
        stats = data.get("analysis_stats", {})

        if not isinstance(stats, dict):
            stats = {}

        malicious = self._safe_int(stats.get("malicious"))
        suspicious = self._safe_int(stats.get("suspicious"))
        total_engines = self._safe_int(data.get("total_engines"))
        reputation = self._safe_int(data.get("reputation"))

        if total_engines <= 0:
            total_engines = sum(
                self._safe_int(stats.get(key))
                for key in (
                    "malicious",
                    "suspicious",
                    "harmless",
                    "undetected",
                    "timeout",
                )
            )

        detection_percentage = (
            ((malicious + suspicious) / total_engines) * 100
            if total_engines > 0
            else 0.0
        )

        score = min(
            100.0,
            detection_percentage * 2.5
            + min(malicious * 3.0, 45.0)
            + min(suspicious * 1.5, 15.0),
        )

        evidence: list[str] = []

        if malicious > 0:
            evidence.append(
                f"VirusTotal: {malicious} engine(s) marked the IOC malicious."
            )

        if suspicious > 0:
            evidence.append(
                f"VirusTotal: {suspicious} engine(s) marked the IOC suspicious."
            )

        if total_engines > 0:
            evidence.append(
                "VirusTotal detection ratio: "
                f"{round(detection_percentage, 2)}% "
                f"across {total_engines} engines."
            )

        # Positive VirusTotal community reputation reduces weak false positives.
        if reputation >= 100 and malicious <= 1:
            score = max(0.0, score - 20.0)
            evidence.append(
                "VirusTotal reports strong positive community reputation."
            )

        elif reputation <= -50:
            score = min(100.0, score + 15.0)
            evidence.append(
                "VirusTotal reports strongly negative community reputation."
            )

        return {
            "score": round(score, 2),
            "weight": self.SOURCE_WEIGHTS["virustotal"],
            "malicious_engines": malicious,
            "suspicious_engines": suspicious,
            "total_engines": total_engines,
            "detection_ratio_percent": round(detection_percentage, 2),
            "reputation": reputation,
            "verdict": data.get("verdict"),
            "evidence": evidence,
        }

    def _score_abuseipdb(
        self,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Calculate an AbuseIPDB risk component."""
        abuse_score = self._clamp_score(
            data.get("abuse_confidence_score")
        )
        total_reports = self._safe_int(data.get("total_reports"))
        distinct_users = self._safe_int(
            data.get("num_distinct_users")
        )
        is_whitelisted = data.get("is_whitelisted")

        score = float(abuse_score)
        evidence: list[str] = []

        evidence.append(
            f"AbuseIPDB confidence score: {abuse_score}/100."
        )

        if total_reports > 0:
            evidence.append(
                f"AbuseIPDB contains {total_reports} report(s) "
                f"from {distinct_users} distinct reporter(s)."
            )

        # Report counts matter only when supported by a non-zero confidence.
        if abuse_score > 0:
            score += min(distinct_users * 0.3, 10.0)

        if is_whitelisted is True and abuse_score < 25:
            score = min(score, 5.0)
            evidence.append(
                "AbuseIPDB identifies the address as whitelisted."
            )

        return {
            "score": round(min(score, 100.0), 2),
            "weight": self.SOURCE_WEIGHTS["abuseipdb"],
            "abuse_confidence_score": abuse_score,
            "total_reports": total_reports,
            "num_distinct_users": distinct_users,
            "is_whitelisted": is_whitelisted,
            "verdict": data.get("verdict"),
            "evidence": evidence,
        }

    def _score_history(
        self,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Calculate risk from persistent incident memory."""
        occurrence_count = self._safe_int(
            data.get(
                "occurrence_count",
                data.get("historical_incident_count", 0),
            )
        )

        repeat_offender = bool(
            data.get(
                "is_repeat_offender",
                occurrence_count >= 2,
            )
        )

        previous_max_risk = self._clamp_score(
            data.get(
                "highest_historical_risk_score",
                data.get("max_risk_score", 0),
            )
        )

        score = min(
            100.0,
            occurrence_count * 8.0
            + (20.0 if repeat_offender else 0.0)
            + previous_max_risk * 0.35,
        )

        evidence: list[str] = []

        if occurrence_count > 0:
            evidence.append(
                f"Incident memory: IOC appeared in "
                f"{occurrence_count} historical incident(s)."
            )

        if repeat_offender:
            evidence.append(
                "Incident memory identifies the IOC as a repeat offender."
            )

        if previous_max_risk > 0:
            evidence.append(
                f"Highest historical incident risk: "
                f"{previous_max_risk}/100."
            )

        return {
            "score": round(score, 2),
            "weight": self.SOURCE_WEIGHTS["history"],
            "occurrence_count": occurrence_count,
            "is_repeat_offender": repeat_offender,
            "highest_historical_risk_score": previous_max_risk,
            "evidence": evidence,
        }

    def _score_local_evidence(
        self,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Calculate risk from the current detection context."""
        severity = str(data.get("severity", "")).strip().lower()
        confidence = str(data.get("confidence", "")).strip().lower()
        detection_count = self._safe_int(
            data.get("detection_count", 0)
        )

        severity_scores = {
            "informational": 5,
            "info": 5,
            "low": 20,
            "medium": 45,
            "high": 70,
            "critical": 95,
        }

        confidence_modifiers = {
            "low": -10,
            "medium": 0,
            "high": 10,
        }

        score = float(severity_scores.get(severity, 0))
        score += confidence_modifiers.get(confidence, 0)
        score += min(detection_count * 2, 10)
        score = max(0.0, min(score, 100.0))

        evidence: list[str] = []

        if severity:
            evidence.append(
                f"Current local detection severity: {severity.upper()}."
            )

        if confidence:
            evidence.append(
                f"Current local detection confidence: {confidence.upper()}."
            )

        if detection_count > 0:
            evidence.append(
                f"Current incident contains {detection_count} "
                f"matching detection(s)."
            )

        return {
            "score": round(score, 2),
            "weight": self.SOURCE_WEIGHTS["local_evidence"],
            "severity": severity or None,
            "confidence": confidence or None,
            "detection_count": detection_count,
            "evidence": evidence,
        }

    def _combine_components(
        self,
        components: dict[str, dict[str, Any]],
    ) -> float:
        """
        Combine only available evidence sources.

        Weights are renormalized when a source is unavailable.
        """
        if not components:
            return 0.0

        total_weight = sum(
            self._safe_float(component.get("weight"))
            for component in components.values()
        )

        if total_weight <= 0:
            return 0.0

        weighted_total = sum(
            self._safe_float(component.get("score"))
            * self._safe_float(component.get("weight"))
            for component in components.values()
        )

        return round(weighted_total / total_weight, 2)

    def _apply_contextual_adjustments(
        self,
        score: float,
        virustotal: dict[str, Any] | None,
        abuseipdb: dict[str, Any] | None,
        history: dict[str, Any] | None,
        local_evidence: dict[str, Any] | None,
    ) -> int:
        """Apply deterministic cross-source contextual adjustments."""
        adjusted = float(score)

        vt_stats = (
            virustotal.get("analysis_stats", {})
            if isinstance(virustotal, dict)
            else {}
        )

        malicious = (
            self._safe_int(vt_stats.get("malicious"))
            if isinstance(vt_stats, dict)
            else 0
        )

        abuse_score = (
            self._clamp_score(
                abuseipdb.get("abuse_confidence_score")
            )
            if isinstance(abuseipdb, dict)
            else 0
        )

        whitelisted = (
            abuseipdb.get("is_whitelisted") is True
            if isinstance(abuseipdb, dict)
            else False
        )

        repeat_offender = (
            bool(history.get("is_repeat_offender"))
            if isinstance(history, dict)
            else False
        )

        local_severity = (
            str(local_evidence.get("severity", "")).lower()
            if isinstance(local_evidence, dict)
            else ""
        )

        # Strong independent agreement increases risk.
        if malicious >= 5 and abuse_score >= 70:
            adjusted += 15

        if malicious >= 10 and abuse_score >= 90:
            adjusted += 10

        if repeat_offender:
            adjusted += 8

        if local_severity == "critical":
            adjusted += 8

        # Whitelisting can suppress weak signals but never strong evidence.
        if (
            whitelisted
            and abuse_score < 25
            and malicious <= 1
            and not repeat_offender
            and local_severity not in {"high", "critical"}
        ):
            adjusted = min(adjusted, 15)

        return int(round(max(0.0, min(adjusted, 100.0))))

    def _detect_contradictions(
        self,
        virustotal: dict[str, Any] | None,
        abuseipdb: dict[str, Any] | None,
        history: dict[str, Any] | None,
    ) -> list[str]:
        """Identify disagreements between trusted evidence sources."""
        contradictions: list[str] = []

        vt_stats = (
            virustotal.get("analysis_stats", {})
            if isinstance(virustotal, dict)
            else {}
        )

        malicious = (
            self._safe_int(vt_stats.get("malicious"))
            if isinstance(vt_stats, dict)
            else 0
        )

        abuse_score = (
            self._clamp_score(
                abuseipdb.get("abuse_confidence_score")
            )
            if isinstance(abuseipdb, dict)
            else 0
        )

        whitelisted = (
            abuseipdb.get("is_whitelisted") is True
            if isinstance(abuseipdb, dict)
            else False
        )

        repeat_offender = (
            bool(history.get("is_repeat_offender"))
            if isinstance(history, dict)
            else False
        )

        if whitelisted and malicious >= 3:
            contradictions.append(
                "AbuseIPDB whitelists the IOC, but VirusTotal has "
                "multiple malicious detections."
            )

        if abuse_score >= 70 and malicious == 0:
            contradictions.append(
                "AbuseIPDB reports strong abuse confidence, while "
                "VirusTotal reports no malicious detections."
            )

        if whitelisted and repeat_offender:
            contradictions.append(
                "The IOC is externally whitelisted but repeatedly appears "
                "in local incident history."
            )

        return contradictions

    def _derive_confidence(
        self,
        components: dict[str, dict[str, Any]],
        contradictions: list[str],
    ) -> str:
        """Derive confidence from meaningful evidence-source coverage."""
        meaningful_source_count = sum(
            bool(component.get("evidence"))
            for component in components.values()
        )

        if meaningful_source_count >= 3 and not contradictions:
            return "High"

        if meaningful_source_count >= 2 and len(contradictions) <= 1:
            return "Medium"

        return "Low"

    @staticmethod
    def _derive_verdict(score: int) -> str:
        """Map the final score to a deterministic verdict."""
        if score >= 85:
            return "confirmed_malicious"

        if score >= 65:
            return "likely_malicious"

        if score >= 40:
            return "suspicious"

        if score >= 16:
            return "low_risk"

        return "trusted"

    @staticmethod
    def _derive_severity(score: int) -> str:
        """Map the final score to SOC severity."""
        if score >= 85:
            return "CRITICAL"

        if score >= 65:
            return "HIGH"

        if score >= 40:
            return "MEDIUM"

        if score >= 16:
            return "LOW"

        return "INFORMATIONAL"

    @staticmethod
    def _recommended_action(
        score: int,
        confidence: str,
    ) -> str:
        """Return a deterministic analyst action."""
        if score >= 85 and confidence in {"High", "Medium"}:
            return "block_and_escalate"

        if score >= 65:
            return "contain_and_investigate"

        if score >= 40:
            return "create_ticket_and_investigate"

        if score >= 16:
            return "monitor"

        return "allow_with_logging"

    @staticmethod
    def _provider_count(
        virustotal: dict[str, Any] | None,
        abuseipdb: dict[str, Any] | None,
    ) -> int:
        """Count available external intelligence providers."""
        return sum(
            isinstance(provider, dict)
            for provider in (virustotal, abuseipdb)
        )

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
        """Clamp a numeric score to the inclusive range 0–100."""
        return max(0, min(cls._safe_int(value), 100))

    @staticmethod
    def _deduplicate_strings(values: list[str]) -> list[str]:
        """Deduplicate strings while preserving their original order."""
        return list(dict.fromkeys(value for value in values if value))