from __future__ import annotations

import inspect
import ipaddress
from typing import Any, Dict, List, Optional, Set

from ..agent_base import BaseInvestigationAgent
from ..investigation_models import (
    AgentExecutionResult,
    AgentFinding,
    Evidence,
    EvidenceType,
    InvestigationTask,
    TaskPriority,
)

try:
    from threat_intelligence import (
        AbuseIPDBClient,
        IntelligenceCorrelator,
        IntelligenceSummaryBuilder,
        ReputationEngine,
        VirusTotalClient,
    )

    THREAT_INTELLIGENCE_AVAILABLE = True

except ImportError:
    AbuseIPDBClient = None  # type: ignore[assignment]
    IntelligenceCorrelator = None  # type: ignore[assignment]
    IntelligenceSummaryBuilder = None  # type: ignore[assignment]
    ReputationEngine = None  # type: ignore[assignment]
    VirusTotalClient = None  # type: ignore[assignment]

    THREAT_INTELLIGENCE_AVAILABLE = False


class ThreatIntelAgent(BaseInvestigationAgent):
    """
    Enriches indicators using the existing threat-intelligence package.

    Responsibilities:
    - Read normalized indicators from task input and shared context
    - Query supported threat-intelligence providers
    - Handle missing API keys and provider failures safely
    - Merge provider findings through the reputation engine
    - Correlate intelligence with incident history
    - Generate an analyst-readable intelligence summary
    - Publish evidence and shared intelligence state
    """

    agent_name = "threat_intel_agent"
    description = (
        "Enriches indicators using configured threat-intelligence "
        "providers, reputation scoring, and historical correlation."
    )
    version = "0.7.0"

    @property
    def supported_task_types(self) -> Set[str]:
        return {
            "threat_intelligence",
            "threat_intel_enrichment",
            "ioc_enrichment",
            "reputation_analysis",
        }

    @staticmethod
    def _flatten_values(value: Any) -> List[str]:
        """Flatten nested IOC values into strings."""

        flattened: List[str] = []

        if value is None:
            return flattened

        if isinstance(value, str):
            normalized = value.strip()

            if normalized:
                flattened.append(normalized)

            return flattened

        if isinstance(value, dict):
            for nested_value in value.values():
                flattened.extend(
                    ThreatIntelAgent._flatten_values(
                        nested_value
                    )
                )

            return flattened

        if isinstance(value, (list, tuple, set)):
            for item in value:
                flattened.extend(
                    ThreatIntelAgent._flatten_values(item)
                )

            return flattened

        flattened.append(str(value).strip())

        return flattened

    @staticmethod
    def _deduplicate(values: List[str]) -> List[str]:
        """Deduplicate values while preserving order."""

        seen: Set[str] = set()
        result: List[str] = []

        for value in values:
            normalized = value.strip()

            if normalized and normalized not in seen:
                seen.add(normalized)
                result.append(normalized)

        return result

    @staticmethod
    def _is_public_ip(value: str) -> bool:
        """Return True only for globally routable IP addresses."""

        try:
            ip_object = ipaddress.ip_address(value)

            return ip_object.is_global

        except ValueError:
            return False

    def _collect_iocs(
        self,
        task: InvestigationTask,
    ) -> Dict[str, List[str]]:
        """Collect IOCs from task input and shared IOC state."""

        input_data = dict(task.input_data or {})

        shared_iocs = self.get_shared_value(
            "normalized_iocs",
            {},
        )

        shared_normalized: Dict[str, Any] = {}

        if isinstance(shared_iocs, dict):
            possible_normalized = shared_iocs.get(
                "normalized",
                shared_iocs,
            )

            if isinstance(possible_normalized, dict):
                shared_normalized = possible_normalized

        ips = self._deduplicate(
            self._flatten_values(
                input_data.get(
                    "ips",
                    input_data.get(
                        "source_ips",
                        input_data.get(
                            "ip_addresses",
                            [],
                        ),
                    ),
                )
            )
            + self._flatten_values(
                shared_normalized.get("ips", [])
            )
        )

        domains = self._deduplicate(
            self._flatten_values(
                input_data.get("domains", [])
            )
            + self._flatten_values(
                shared_normalized.get("domains", [])
            )
        )

        urls = self._deduplicate(
            self._flatten_values(
                input_data.get("urls", [])
            )
            + self._flatten_values(
                shared_normalized.get("urls", [])
            )
        )

        hashes = self._deduplicate(
            self._flatten_values(
                input_data.get("hashes", [])
            )
            + self._flatten_values(
                shared_normalized.get("hashes", [])
            )
        )

        return {
            "ips": ips,
            "domains": domains,
            "urls": urls,
            "hashes": hashes,
        }

    @staticmethod
    def _instantiate_component(
        component_class: Any,
        configuration: Dict[str, Any],
    ) -> Any:
        """
        Instantiate a project component while tolerating constructor
        differences between versions.
        """

        if component_class is None:
            return None

        try:
            signature = inspect.signature(
                component_class
            )

            accepted_arguments = {}

            for parameter_name in signature.parameters:
                if parameter_name in configuration:
                    accepted_arguments[parameter_name] = (
                        configuration[parameter_name]
                    )

            return component_class(
                **accepted_arguments
            )

        except (TypeError, ValueError):
            try:
                return component_class()

            except Exception:
                return None

    @staticmethod
    def _call_first_available(
        component: Any,
        method_names: List[str],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """
        Call the first compatible method exposed by a component.

        This keeps the agent compatible if your existing threat-intel
        classes use method names such as:
        - lookup_ip
        - check_ip
        - analyze_ip
        - get_reputation
        - enrich
        """

        if component is None:
            return None

        for method_name in method_names:
            method = getattr(
                component,
                method_name,
                None,
            )

            if not callable(method):
                continue

            try:
                return method(*args, **kwargs)

            except TypeError:
                try:
                    return method(*args)

                except TypeError:
                    try:
                        return method(
                            observable=args[0]
                            if args
                            else None
                        )

                    except TypeError:
                        continue

        return None

    @staticmethod
    def _normalize_result(
        result: Any,
        provider: str,
        observable: str,
    ) -> Dict[str, Any]:
        """Convert provider output into a serializable dictionary."""

        if result is None:
            return {
                "provider": provider,
                "observable": observable,
                "status": "unavailable",
                "data": {},
            }

        if isinstance(result, dict):
            normalized = dict(result)

        elif hasattr(result, "to_dict") and callable(
            result.to_dict
        ):
            normalized = result.to_dict()

        elif hasattr(result, "__dict__"):
            normalized = dict(result.__dict__)

        else:
            normalized = {
                "raw_result": str(result),
            }

        return {
            "provider": provider,
            "observable": observable,
            "status": "success",
            "data": normalized,
        }

    def _query_virustotal(
        self,
        client: Any,
        observable: str,
        observable_type: str,
    ) -> Dict[str, Any]:
        """Query VirusTotal through the existing client."""

        method_map = {
            "ip": [
                "lookup_ip",
                "check_ip",
                "analyze_ip",
                "get_ip_report",
                "get_ip_reputation",
                "enrich_ip",
                "enrich",
            ],
            "domain": [
                "lookup_domain",
                "check_domain",
                "analyze_domain",
                "get_domain_report",
                "enrich_domain",
                "enrich",
            ],
            "url": [
                "lookup_url",
                "check_url",
                "analyze_url",
                "get_url_report",
                "enrich_url",
                "enrich",
            ],
            "hash": [
                "lookup_hash",
                "check_hash",
                "analyze_hash",
                "get_file_report",
                "enrich_hash",
                "enrich",
            ],
        }

        result = self._call_first_available(
            client,
            method_map.get(
                observable_type,
                ["enrich"],
            ),
            observable,
        )

        return self._normalize_result(
            result=result,
            provider="virustotal",
            observable=observable,
        )

    def _query_abuseipdb(
        self,
        client: Any,
        ip_address: str,
    ) -> Dict[str, Any]:
        """Query AbuseIPDB through the existing client."""

        result = self._call_first_available(
            client,
            [
                "lookup_ip",
                "check_ip",
                "analyze_ip",
                "get_ip_report",
                "get_ip_reputation",
                "enrich_ip",
                "enrich",
            ],
            ip_address,
        )

        return self._normalize_result(
            result=result,
            provider="abuseipdb",
            observable=ip_address,
        )

    def _run_reputation_engine(
        self,
        engine: Any,
        observable: str,
        provider_results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Merge provider results through the reputation engine."""

        result = self._call_first_available(
            engine,
            [
                "evaluate",
                "analyze",
                "calculate_reputation",
                "calculate_risk",
                "score",
                "build_reputation",
            ],
            observable,
            provider_results,
        )

        if result is None:
            result = self._call_first_available(
                engine,
                [
                    "evaluate",
                    "analyze",
                    "calculate_reputation",
                    "calculate_risk",
                    "score",
                    "build_reputation",
                ],
                provider_results,
            )

        normalized = self._normalize_result(
            result=result,
            provider="reputation_engine",
            observable=observable,
        )

        return normalized["data"]

    def _run_correlation(
        self,
        correlator: Any,
        observable: str,
        reputation: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Correlate an observable with historical incident memory."""

        result = self._call_first_available(
            correlator,
            [
                "correlate",
                "correlate_ioc",
                "analyze",
                "find_matches",
                "correlate_with_history",
            ],
            observable,
            reputation,
        )

        if result is None:
            result = self._call_first_available(
                correlator,
                [
                    "correlate",
                    "correlate_ioc",
                    "analyze",
                    "find_matches",
                    "correlate_with_history",
                ],
                observable,
            )

        normalized = self._normalize_result(
            result=result,
            provider="intelligence_correlator",
            observable=observable,
        )

        return normalized["data"]

    def _build_intelligence_summary(
        self,
        builder: Any,
        observable: str,
        provider_results: List[Dict[str, Any]],
        reputation: Dict[str, Any],
        correlation: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate an analyst-facing intelligence summary."""

        result = self._call_first_available(
            builder,
            [
                "build",
                "build_summary",
                "generate",
                "generate_summary",
                "summarize",
            ],
            observable,
            provider_results,
            reputation,
            correlation,
        )

        if result is None:
            result = self._call_first_available(
                builder,
                [
                    "build",
                    "build_summary",
                    "generate",
                    "generate_summary",
                    "summarize",
                ],
                {
                    "observable": observable,
                    "provider_results": provider_results,
                    "reputation": reputation,
                    "correlation": correlation,
                },
            )

        normalized = self._normalize_result(
            result=result,
            provider="intelligence_summary",
            observable=observable,
        )

        return normalized["data"]

    @staticmethod
    def _extract_numeric_value(
        data: Dict[str, Any],
        keys: List[str],
        default: int = 0,
    ) -> int:
        """Extract a numeric value from nested intelligence data."""

        for key in keys:
            value = data.get(key)

            if isinstance(value, bool):
                continue

            if isinstance(value, (int, float)):
                return int(value)

            try:
                if value is not None:
                    return int(float(str(value)))

            except (TypeError, ValueError):
                pass

        for nested_value in data.values():
            if isinstance(nested_value, dict):
                extracted = (
                    ThreatIntelAgent._extract_numeric_value(
                        nested_value,
                        keys,
                        default,
                    )
                )

                if extracted != default:
                    return extracted

        return default

    @staticmethod
    def _extract_text_value(
        data: Dict[str, Any],
        keys: List[str],
        default: str = "",
    ) -> str:
        """Extract a text value from nested intelligence data."""

        for key in keys:
            value = data.get(key)

            if value is not None:
                normalized = str(value).strip()

                if normalized:
                    return normalized

        for nested_value in data.values():
            if isinstance(nested_value, dict):
                extracted = (
                    ThreatIntelAgent._extract_text_value(
                        nested_value,
                        keys,
                        default,
                    )
                )

                if extracted != default:
                    return extracted

        return default

    def _determine_verdict(
        self,
        reputation: Dict[str, Any],
        summary: Dict[str, Any],
        provider_results: List[Dict[str, Any]],
    ) -> str:
        """Determine a normalized intelligence verdict."""

        combined_data = {
            "reputation": reputation,
            "summary": summary,
            "providers": provider_results,
        }

        verdict = self._extract_text_value(
            combined_data,
            [
                "verdict",
                "classification",
                "reputation_verdict",
                "threat_verdict",
            ],
        ).lower()

        verdict_aliases = {
            "clean": "trusted",
            "safe": "trusted",
            "benign": "trusted",
            "known_good": "trusted",
            "high risk": "malicious",
            "high_risk": "malicious",
            "confirmed malicious": "confirmed_malicious",
        }

        verdict = verdict_aliases.get(
            verdict,
            verdict,
        )

        if verdict in {
            "trusted",
            "malicious",
            "confirmed_malicious",
            "suspicious",
            "unknown",
        }:
            return verdict

        risk_score = self._extract_numeric_value(
            combined_data,
            [
                "risk_score",
                "combined_risk_score",
                "score",
            ],
        )

        if risk_score >= 90:
            return "confirmed_malicious"

        if risk_score >= 70:
            return "malicious"

        if risk_score >= 40:
            return "suspicious"

        if risk_score > 0:
            return "trusted"

        return "unknown"

    @staticmethod
    def _severity_from_verdict(
        verdict: str,
        risk_score: int,
    ) -> str:
        """Convert intelligence outcome into SOC severity."""

        if (
            verdict == "confirmed_malicious"
            or risk_score >= 90
        ):
            return "CRITICAL"

        if (
            verdict == "malicious"
            or risk_score >= 70
        ):
            return "HIGH"

        if (
            verdict == "suspicious"
            or risk_score >= 40
        ):
            return "MEDIUM"

        if verdict == "trusted":
            return "INFORMATIONAL"

        return "LOW"

    @staticmethod
    def _confidence_from_results(
        provider_results: List[Dict[str, Any]],
        reputation: Dict[str, Any],
    ) -> float:
        """Calculate deterministic intelligence confidence."""

        successful_provider_count = sum(
            1
            for result in provider_results
            if result.get("status") == "success"
        )

        confidence = 0.40

        if successful_provider_count == 1:
            confidence = 0.70

        elif successful_provider_count >= 2:
            confidence = 0.88

        explicit_confidence = (
            ThreatIntelAgent._extract_numeric_value(
                reputation,
                ["confidence", "confidence_score"],
                default=0,
            )
        )

        if explicit_confidence:
            if explicit_confidence > 1:
                explicit_confidence = (
                    explicit_confidence / 100
                )

            confidence = max(
                confidence,
                min(float(explicit_confidence), 0.98),
            )

        return round(confidence, 2)

    def _enrich_observable(
        self,
        observable: str,
        observable_type: str,
        vt_client: Any,
        abuse_client: Any,
        reputation_engine: Any,
        correlator: Any,
        summary_builder: Any,
    ) -> Dict[str, Any]:
        """Run the complete enrichment pipeline for one observable."""

        provider_results: List[Dict[str, Any]] = []

        vt_result = self._query_virustotal(
            client=vt_client,
            observable=observable,
            observable_type=observable_type,
        )

        provider_results.append(vt_result)

        if (
            observable_type == "ip"
            and self._is_public_ip(observable)
        ):
            abuse_result = self._query_abuseipdb(
                client=abuse_client,
                ip_address=observable,
            )

            provider_results.append(abuse_result)

        reputation = self._run_reputation_engine(
            engine=reputation_engine,
            observable=observable,
            provider_results=provider_results,
        )

        correlation = self._run_correlation(
            correlator=correlator,
            observable=observable,
            reputation=reputation,
        )

        intelligence_summary = (
            self._build_intelligence_summary(
                builder=summary_builder,
                observable=observable,
                provider_results=provider_results,
                reputation=reputation,
                correlation=correlation,
            )
        )

        combined_data = {
            "reputation": reputation,
            "summary": intelligence_summary,
            "correlation": correlation,
        }

        risk_score = self._extract_numeric_value(
            combined_data,
            [
                "combined_risk_score",
                "risk_score",
                "score",
            ],
        )

        verdict = self._determine_verdict(
            reputation=reputation,
            summary=intelligence_summary,
            provider_results=provider_results,
        )

        severity = self._severity_from_verdict(
            verdict=verdict,
            risk_score=risk_score,
        )

        confidence = self._confidence_from_results(
            provider_results=provider_results,
            reputation=reputation,
        )

        return {
            "observable": observable,
            "observable_type": observable_type,
            "provider_results": provider_results,
            "reputation": reputation,
            "correlation": correlation,
            "intelligence_summary": intelligence_summary,
            "risk_score": risk_score,
            "verdict": verdict,
            "severity": severity,
            "confidence": confidence,
        }

    def _build_follow_up_tasks(
        self,
        task: InvestigationTask,
        enriched_observables: List[Dict[str, Any]],
    ) -> List[InvestigationTask]:
        """Build intelligence-dependent follow-up tasks."""

        malicious_observables = [
            result
            for result in enriched_observables
            if result["verdict"]
            in {
                "malicious",
                "confirmed_malicious",
                "suspicious",
            }
        ]

        if not malicious_observables:
            return []

        priority = (
            TaskPriority.P1
            if any(
                result["severity"] == "CRITICAL"
                for result in malicious_observables
            )
            else TaskPriority.P2
        )

        compact_results = [
            {
                "observable": result["observable"],
                "observable_type": (
                    result["observable_type"]
                ),
                "risk_score": result["risk_score"],
                "verdict": result["verdict"],
                "severity": result["severity"],
                "confidence": result["confidence"],
            }
            for result in malicious_observables
        ]

        return [
            InvestigationTask(
                task_type="historical_correlation",
                assigned_agent="correlation_agent",
                description=(
                    "Correlate malicious threat-intelligence "
                    "observables with historical incidents."
                ),
                priority=priority,
                input_data={
                    "threat_intelligence_results": (
                        compact_results
                    )
                },
                dependencies=[task.task_id],
            ),
            InvestigationTask(
                task_type="root_cause_analysis",
                assigned_agent="root_cause_agent",
                description=(
                    "Use threat-intelligence findings during attack "
                    "chain and root-cause analysis."
                ),
                priority=priority,
                input_data={
                    "threat_intelligence_results": (
                        compact_results
                    )
                },
                dependencies=[task.task_id],
            ),
            InvestigationTask(
                task_type="response_recommendation",
                assigned_agent="response_advisor_agent",
                description=(
                    "Recommend response actions based on confirmed "
                    "or suspicious intelligence findings."
                ),
                priority=priority,
                input_data={
                    "threat_intelligence_results": (
                        compact_results
                    )
                },
                dependencies=[task.task_id],
            ),
        ]

    def execute_task(
        self,
        task: InvestigationTask,
    ) -> AgentExecutionResult:
        """Execute the threat-intelligence enrichment workflow."""

        iocs = self._collect_iocs(task)

        observable_records = [
            ("ip", value)
            for value in iocs["ips"]
        ]

        observable_records.extend(
            ("domain", value)
            for value in iocs["domains"]
        )

        observable_records.extend(
            ("url", value)
            for value in iocs["urls"]
        )

        observable_records.extend(
            ("hash", value)
            for value in iocs["hashes"]
        )

        if not observable_records:
            summary = (
                "Threat-intelligence enrichment completed with no "
                "available indicators to analyze."
            )

            finding = AgentFinding(
                agent_name=self.agent_name,
                title="Threat Intelligence Enrichment",
                summary=summary,
                severity="INFORMATIONAL",
                confidence=0.35,
                recommendations=[
                    (
                        "Provide normalized public IP addresses, "
                        "domains, URLs, or file hashes."
                    )
                ],
                metadata={
                    "observable_count": 0,
                    "package_available": (
                        THREAT_INTELLIGENCE_AVAILABLE
                    ),
                },
            )

            return self.create_success_result(
                summary=summary,
                findings=[finding],
                metadata={
                    "observable_count": 0,
                    "enriched_count": 0,
                },
            )

        component_configuration = dict(
            self.configuration
        )

        vt_client = self._instantiate_component(
            VirusTotalClient,
            component_configuration,
        )

        abuse_client = self._instantiate_component(
            AbuseIPDBClient,
            component_configuration,
        )

        reputation_engine = self._instantiate_component(
            ReputationEngine,
            component_configuration,
        )

        correlator = self._instantiate_component(
            IntelligenceCorrelator,
            component_configuration,
        )

        summary_builder = self._instantiate_component(
            IntelligenceSummaryBuilder,
            component_configuration,
        )

        enriched_observables: List[Dict[str, Any]] = []

        for observable_type, observable in observable_records:
            enriched_observables.append(
                self._enrich_observable(
                    observable=observable,
                    observable_type=observable_type,
                    vt_client=vt_client,
                    abuse_client=abuse_client,
                    reputation_engine=reputation_engine,
                    correlator=correlator,
                    summary_builder=summary_builder,
                )
            )

        highest_risk_score = max(
            (
                result["risk_score"]
                for result in enriched_observables
            ),
            default=0,
        )

        malicious_count = sum(
            1
            for result in enriched_observables
            if result["verdict"]
            in {
                "malicious",
                "confirmed_malicious",
            }
        )

        suspicious_count = sum(
            1
            for result in enriched_observables
            if result["verdict"] == "suspicious"
        )

        trusted_count = sum(
            1
            for result in enriched_observables
            if result["verdict"] == "trusted"
        )

        unknown_count = sum(
            1
            for result in enriched_observables
            if result["verdict"] == "unknown"
        )

        highest_severity = "INFORMATIONAL"

        severity_order = {
            "INFORMATIONAL": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        for result in enriched_observables:
            if (
                severity_order.get(
                    result["severity"],
                    0,
                )
                > severity_order.get(
                    highest_severity,
                    0,
                )
            ):
                highest_severity = result["severity"]

        average_confidence = round(
            sum(
                result["confidence"]
                for result in enriched_observables
            )
            / len(enriched_observables),
            2,
        )

        summary = (
            f"Threat-intelligence enrichment analyzed "
            f"{len(enriched_observables)} observable(s). "
            f"Results: {malicious_count} malicious, "
            f"{suspicious_count} suspicious, "
            f"{trusted_count} trusted, and "
            f"{unknown_count} unknown. "
            f"Highest risk score: {highest_risk_score}/100."
        )

        evidence: List[Evidence] = []

        for result in enriched_observables:
            evidence.append(
                Evidence(
                    evidence_type=(
                        EvidenceType.THREAT_INTELLIGENCE
                    ),
                    source=self.agent_name,
                    value=result,
                    description=(
                        "Threat-intelligence enrichment for "
                        f"{result['observable_type']} observable "
                        f"{result['observable']}."
                    ),
                    confidence=result["confidence"],
                    tags=[
                        "threat_intelligence",
                        result["observable_type"],
                        result["verdict"],
                        result["severity"].lower(),
                    ],
                )
            )

        finding = AgentFinding(
            agent_name=self.agent_name,
            title="Threat Intelligence Enrichment",
            summary=summary,
            severity=highest_severity,
            confidence=average_confidence,
            evidence_ids=[
                evidence_item.evidence_id
                for evidence_item in evidence
            ],
            recommendations=[
                (
                    "Prioritize confirmed malicious and high-risk "
                    "observables for containment review."
                ),
                (
                    "Correlate suspicious observables with historical "
                    "incidents before final disposition."
                ),
                (
                    "Do not automatically block trusted or unknown "
                    "observables without supporting evidence."
                ),
            ],
            metadata={
                "observable_count": len(
                    enriched_observables
                ),
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "trusted_count": trusted_count,
                "unknown_count": unknown_count,
                "highest_risk_score": highest_risk_score,
                "highest_severity": highest_severity,
                "package_available": (
                    THREAT_INTELLIGENCE_AVAILABLE
                ),
            },
        )

        shared_result = {
            "observables": enriched_observables,
            "summary": {
                "observable_count": len(
                    enriched_observables
                ),
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "trusted_count": trusted_count,
                "unknown_count": unknown_count,
                "highest_risk_score": highest_risk_score,
                "highest_severity": highest_severity,
                "confidence": average_confidence,
            },
        }

        self.set_shared_value(
            key="threat_intelligence_results",
            value=shared_result,
        )

        self.send_message(
            recipient_agent="correlation_agent",
            subject="Threat-intelligence enrichment ready",
            content=summary,
            message_type="threat_intelligence_result",
            related_task_id=task.task_id,
            related_evidence_ids=[
                evidence_item.evidence_id
                for evidence_item in evidence
            ],
            metadata={
                "highest_risk_score": highest_risk_score,
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
            },
        )

        self.send_message(
            recipient_agent="root_cause_agent",
            subject="Threat intelligence ready for analysis",
            content=summary,
            message_type="threat_intelligence_result",
            related_task_id=task.task_id,
            related_evidence_ids=[
                evidence_item.evidence_id
                for evidence_item in evidence
            ],
            metadata={
                "highest_risk_score": highest_risk_score,
                "highest_severity": highest_severity,
            },
        )

        self.send_message(
            recipient_agent="response_advisor_agent",
            subject="Threat intelligence ready for response planning",
            content=summary,
            message_type="threat_intelligence_result",
            related_task_id=task.task_id,
            related_evidence_ids=[
                evidence_item.evidence_id
                for evidence_item in evidence
            ],
            metadata={
                "highest_risk_score": highest_risk_score,
                "highest_severity": highest_severity,
            },
        )

        proposed_tasks = self._build_follow_up_tasks(
            task=task,
            enriched_observables=enriched_observables,
        )

        return self.create_success_result(
            summary=summary,
            findings=[finding],
            evidence=evidence,
            proposed_tasks=proposed_tasks,
            metadata={
                "observable_count": len(
                    enriched_observables
                ),
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "trusted_count": trusted_count,
                "unknown_count": unknown_count,
                "highest_risk_score": highest_risk_score,
                "highest_severity": highest_severity,
                "confidence": average_confidence,
                "enriched_observables": (
                    enriched_observables
                ),
            },
        )