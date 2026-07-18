from __future__ import annotations

import inspect
from typing import Any, Dict, List, Set

from ..agent_base import BaseInvestigationAgent
from ..investigation_models import (
    AgentExecutionResult,
    AgentFinding,
    Evidence,
    EvidenceType,
    InvestigationHypothesis,
    InvestigationTask,
    TaskPriority,
)

try:
    from threat_intelligence import IntelligenceCorrelator
except ImportError:
    IntelligenceCorrelator = None  # type: ignore[assignment]

try:
    from memory.correlation_engine import CorrelationEngine
except ImportError:
    CorrelationEngine = None  # type: ignore[assignment]

try:
    from memory.incident_store import IncidentStore
except ImportError:
    IncidentStore = None  # type: ignore[assignment]

try:
    from memory.timeline import IncidentTimeline
except ImportError:
    IncidentTimeline = None  # type: ignore[assignment]


class CorrelationAgent(BaseInvestigationAgent):
    """
    Correlates the current investigation with historical incident memory.

    Responsibilities:
    - Collect IOCs, MITRE techniques, hosts, users, and threat-intel results
    - Query existing incident-memory and correlation components
    - Detect repeat offenders
    - Identify related incidents and recurring ATT&CK techniques
    - Calculate correlation strength and investigation priority
    - Publish evidence for root-cause and response agents
    """

    agent_name = "correlation_agent"
    description = (
        "Correlates current indicators and behaviors with historical "
        "incidents, repeat offenders, and recurring attack patterns."
    )
    version = "0.7.0"

    @property
    def supported_task_types(self) -> Set[str]:
        return {
            "historical_correlation",
            "incident_correlation",
            "ioc_correlation",
            "timeline_correlation",
            "repeat_offender_analysis",
        }

    @staticmethod
    def _flatten_values(value: Any) -> List[str]:
        """Flatten nested data into normalized strings."""

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
                    CorrelationAgent._flatten_values(
                        nested_value
                    )
                )

            return flattened

        if isinstance(value, (list, tuple, set)):
            for item in value:
                flattened.extend(
                    CorrelationAgent._flatten_values(item)
                )

            return flattened

        flattened.append(str(value).strip())

        return flattened

    @staticmethod
    def _deduplicate(values: List[str]) -> List[str]:
        """Deduplicate strings while preserving order."""

        seen: Set[str] = set()
        results: List[str] = []

        for value in values:
            normalized = value.strip()

            if normalized and normalized not in seen:
                seen.add(normalized)
                results.append(normalized)

        return results

    @staticmethod
    def _to_dict(value: Any) -> Dict[str, Any]:
        """Convert component output into a serializable dictionary."""

        if value is None:
            return {}

        if isinstance(value, dict):
            return dict(value)

        if hasattr(value, "to_dict") and callable(
            value.to_dict
        ):
            result = value.to_dict()

            if isinstance(result, dict):
                return result

        if hasattr(value, "__dict__"):
            return dict(value.__dict__)

        return {
            "value": str(value),
        }

    @staticmethod
    def _instantiate_component(
        component_class: Any,
        configuration: Dict[str, Any],
    ) -> Any:
        """
        Instantiate an existing project component while tolerating
        constructor differences.
        """

        if component_class is None:
            return None

        try:
            signature = inspect.signature(
                component_class
            )

            arguments: Dict[str, Any] = {}

            for parameter_name in signature.parameters:
                if parameter_name in configuration:
                    arguments[parameter_name] = (
                        configuration[parameter_name]
                    )

            return component_class(**arguments)

        except (TypeError, ValueError):
            try:
                return component_class()
            except Exception:
                return None

        except Exception:
            return None

    @staticmethod
    def _call_first_available(
        component: Any,
        method_names: List[str],
        argument_variants: List[tuple[Any, ...]],
    ) -> Any:
        """
        Call the first compatible method using possible argument forms.
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

            for arguments in argument_variants:
                try:
                    return method(*arguments)
                except TypeError:
                    continue
                except Exception as exc:
                    return {
                        "status": "error",
                        "method": method_name,
                        "error": f"{type(exc).__name__}: {exc}",
                    }

        return None

    def _collect_current_entities(
        self,
        task: InvestigationTask,
    ) -> Dict[str, List[str]]:
        """Collect entities from task and shared investigation state."""

        input_data = dict(task.input_data or {})

        normalized_iocs = self.get_shared_value(
            "normalized_iocs",
            {},
        )

        triage = self.get_shared_value(
            "triage_assessment",
            {},
        )

        mitre_mapping = self.get_shared_value(
            "mitre_attack_mapping",
            {},
        )

        threat_intel = self.get_shared_value(
            "threat_intelligence_results",
            {},
        )

        if not isinstance(normalized_iocs, dict):
            normalized_iocs = {}

        if not isinstance(triage, dict):
            triage = {}

        if not isinstance(mitre_mapping, dict):
            mitre_mapping = {}

        if not isinstance(threat_intel, dict):
            threat_intel = {}

        normalized_section = normalized_iocs.get(
            "normalized",
            normalized_iocs,
        )

        if not isinstance(normalized_section, dict):
            normalized_section = {}

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
                normalized_section.get("ips", [])
            )
            + self._flatten_values(
                triage.get("source_ips", [])
            )
        )

        domains = self._deduplicate(
            self._flatten_values(
                input_data.get("domains", [])
            )
            + self._flatten_values(
                normalized_section.get("domains", [])
            )
            + self._flatten_values(
                triage.get("domains", [])
            )
        )

        urls = self._deduplicate(
            self._flatten_values(
                input_data.get("urls", [])
            )
            + self._flatten_values(
                normalized_section.get("urls", [])
            )
        )

        hashes = self._deduplicate(
            self._flatten_values(
                input_data.get("hashes", [])
            )
            + self._flatten_values(
                normalized_section.get("hashes", [])
            )
            + self._flatten_values(
                triage.get("hashes", [])
            )
        )

        hostnames = self._deduplicate(
            self._flatten_values(
                input_data.get(
                    "hostnames",
                    input_data.get("hostname", []),
                )
            )
            + self._flatten_values(
                triage.get("hostnames", [])
            )
        )

        usernames = self._deduplicate(
            self._flatten_values(
                input_data.get(
                    "usernames",
                    input_data.get("username", []),
                )
            )
            + self._flatten_values(
                triage.get("usernames", [])
            )
        )

        mitre_ids = self._deduplicate(
            self._flatten_values(
                input_data.get(
                    "mitre_ids",
                    input_data.get(
                        "technique_ids",
                        [],
                    ),
                )
            )
            + self._flatten_values(
                mitre_mapping.get(
                    "technique_ids",
                    [],
                )
            )
        )

        for record in threat_intel.get(
            "observables",
            [],
        ):
            if not isinstance(record, dict):
                continue

            observable = str(
                record.get("observable", "")
            ).strip()

            observable_type = str(
                record.get("observable_type", "")
            ).strip().lower()

            if not observable:
                continue

            if observable_type == "ip":
                ips.append(observable)

            elif observable_type == "domain":
                domains.append(observable)

            elif observable_type == "url":
                urls.append(observable)

            elif observable_type == "hash":
                hashes.append(observable)

        ips = self._deduplicate(ips)
        domains = self._deduplicate(domains)
        urls = self._deduplicate(urls)
        hashes = self._deduplicate(hashes)

        return {
            "ips": ips,
            "domains": domains,
            "urls": urls,
            "hashes": hashes,
            "hostnames": hostnames,
            "usernames": usernames,
            "mitre_ids": mitre_ids,
        }

    def _build_correlation_payload(
        self,
        entities: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        """Build a common payload for existing correlation components."""

        investigation = self.context.investigation

        return {
            "investigation_id": (
                investigation.investigation_id
            ),
            "incident_id": investigation.incident_id,
            "title": investigation.title,
            "description": investigation.description,
            "severity": investigation.severity,
            "priority": investigation.priority.value,
            "ips": entities["ips"],
            "ip_addresses": entities["ips"],
            "domains": entities["domains"],
            "urls": entities["urls"],
            "hashes": entities["hashes"],
            "hostnames": entities["hostnames"],
            "usernames": entities["usernames"],
            "mitre_ids": entities["mitre_ids"],
            "technique_ids": entities["mitre_ids"],
        }

    def _run_intelligence_correlation(
        self,
        correlator: Any,
        payload: Dict[str, Any],
        entities: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        """Run the v0.5.0 intelligence correlator."""

        observable_results: List[Dict[str, Any]] = []

        all_observables = (
            entities["ips"]
            + entities["domains"]
            + entities["urls"]
            + entities["hashes"]
        )

        for observable in all_observables:
            result = self._call_first_available(
                correlator,
                [
                    "correlate",
                    "correlate_ioc",
                    "analyze",
                    "find_matches",
                    "correlate_with_history",
                ],
                [
                    (observable,),
                    (observable, payload),
                    (payload,),
                ],
            )

            if result is not None:
                observable_results.append(
                    {
                        "observable": observable,
                        "result": self._to_dict(
                            result
                        ),
                    }
                )

        if not observable_results:
            result = self._call_first_available(
                correlator,
                [
                    "correlate",
                    "analyze",
                    "find_matches",
                    "correlate_incident",
                ],
                [
                    (payload,),
                ],
            )

            if result is not None:
                return self._to_dict(result)

        return {
            "observable_results": observable_results,
        }

    def _run_memory_correlation(
        self,
        correlation_engine: Any,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Run the v0.4.0 memory correlation engine."""

        result = self._call_first_available(
            correlation_engine,
            [
                "correlate",
                "correlate_incident",
                "find_similar_incidents",
                "find_matches",
                "analyze",
                "search",
            ],
            [
                (payload,),
                (
                    payload.get("ips", []),
                    payload.get("domains", []),
                    payload.get("mitre_ids", []),
                ),
            ],
        )

        return self._to_dict(result)

    def _load_incident_history(
        self,
        incident_store: Any,
    ) -> List[Dict[str, Any]]:
        """Read stored incidents when the component supports it."""

        result = self._call_first_available(
            incident_store,
            [
                "load_all",
                "get_all_incidents",
                "list_incidents",
                "load_incidents",
                "get_incidents",
            ],
            [
                (),
            ],
        )

        if isinstance(result, list):
            return [
                self._to_dict(item)
                for item in result
            ]

        if isinstance(result, dict):
            possible_incidents = result.get(
                "incidents",
                result.get("items", []),
            )

            if isinstance(possible_incidents, list):
                return [
                    self._to_dict(item)
                    for item in possible_incidents
                ]

        return []

    def _find_direct_history_matches(
        self,
        incidents: List[Dict[str, Any]],
        entities: Dict[str, List[str]],
        current_incident_id: str,
    ) -> List[Dict[str, Any]]:
        """Perform deterministic matching against loaded incidents."""

        matches: List[Dict[str, Any]] = []

        entity_sets = {
            key: set(values)
            for key, values in entities.items()
        }

        for incident in incidents:
            incident_id = str(
                incident.get(
                    "incident_id",
                    incident.get("id", ""),
                )
            )

            if incident_id == current_incident_id:
                continue

            historical_values = {
                "ips": set(
                    self._flatten_values(
                        incident.get(
                            "ips",
                            incident.get(
                                "ip_addresses",
                                incident.get(
                                    "indicators_of_compromise",
                                    {},
                                ).get(
                                    "ips",
                                    [],
                                )
                                if isinstance(
                                    incident.get(
                                        "indicators_of_compromise",
                                        {},
                                    ),
                                    dict,
                                )
                                else [],
                            ),
                        )
                    )
                ),
                "domains": set(
                    self._flatten_values(
                        incident.get(
                            "domains",
                            incident.get(
                                "indicators_of_compromise",
                                {},
                            ).get(
                                "domains",
                                [],
                            )
                            if isinstance(
                                incident.get(
                                    "indicators_of_compromise",
                                    {},
                                ),
                                dict,
                            )
                            else [],
                        )
                    )
                ),
                "hashes": set(
                    self._flatten_values(
                        incident.get(
                            "hashes",
                            incident.get(
                                "indicators_of_compromise",
                                {},
                            ).get(
                                "hashes",
                                [],
                            )
                            if isinstance(
                                incident.get(
                                    "indicators_of_compromise",
                                    {},
                                ),
                                dict,
                            )
                            else [],
                        )
                    )
                ),
                "hostnames": set(
                    self._flatten_values(
                        incident.get(
                            "hostnames",
                            incident.get(
                                "hostname",
                                [],
                            ),
                        )
                    )
                ),
                "usernames": set(
                    self._flatten_values(
                        incident.get(
                            "usernames",
                            incident.get(
                                "username",
                                [],
                            ),
                        )
                    )
                ),
                "mitre_ids": set(
                    self._flatten_values(
                        incident.get(
                            "mitre_ids",
                            incident.get(
                                "technique_ids",
                                [],
                            ),
                        )
                    )
                ),
            }

            overlap: Dict[str, List[str]] = {}

            for entity_type in (
                "ips",
                "domains",
                "hashes",
                "hostnames",
                "usernames",
                "mitre_ids",
            ):
                common_values = sorted(
                    entity_sets.get(
                        entity_type,
                        set(),
                    )
                    & historical_values.get(
                        entity_type,
                        set(),
                    )
                )

                if common_values:
                    overlap[entity_type] = common_values

            if not overlap:
                continue

            match_score = (
                len(overlap.get("ips", [])) * 25
                + len(overlap.get("domains", [])) * 20
                + len(overlap.get("hashes", [])) * 30
                + len(overlap.get("hostnames", [])) * 10
                + len(overlap.get("usernames", [])) * 10
                + len(overlap.get("mitre_ids", [])) * 8
            )

            matches.append(
                {
                    "incident_id": incident_id,
                    "severity": incident.get(
                        "severity",
                        "UNKNOWN",
                    ),
                    "risk_score": incident.get(
                        "risk_score",
                        incident.get(
                            "combined_risk_score",
                            0,
                        ),
                    ),
                    "timestamp": incident.get(
                        "timestamp",
                        incident.get(
                            "created_at",
                            "",
                        ),
                    ),
                    "overlap": overlap,
                    "match_score": min(
                        match_score,
                        100,
                    ),
                }
            )

        return sorted(
            matches,
            key=lambda match: (
                -match["match_score"],
                match["incident_id"],
            ),
        )

    @staticmethod
    def _extract_recursive_values(
        data: Any,
        keys: Set[str],
    ) -> List[Any]:
        """Extract values matching keys from nested structures."""

        results: List[Any] = []

        if isinstance(data, dict):
            for key, value in data.items():
                if key in keys:
                    results.append(value)

                results.extend(
                    CorrelationAgent._extract_recursive_values(
                        value,
                        keys,
                    )
                )

        elif isinstance(data, list):
            for item in data:
                results.extend(
                    CorrelationAgent._extract_recursive_values(
                        item,
                        keys,
                    )
                )

        return results

    def _extract_related_incident_ids(
        self,
        *sources: Any,
    ) -> List[str]:
        """Extract related incident IDs from nested correlation results."""

        values: List[str] = []

        for source in sources:
            extracted = self._extract_recursive_values(
                source,
                {
                    "incident_id",
                    "incident_ids",
                    "related_incident_ids",
                    "matched_incident_ids",
                },
            )

            for value in extracted:
                values.extend(
                    self._flatten_values(value)
                )

        current_incident_id = (
            self.context.investigation.incident_id
        )

        return [
            value
            for value in self._deduplicate(values)
            if value != current_incident_id
        ]

    def _detect_repeat_offender(
        self,
        entities: Dict[str, List[str]],
        direct_matches: List[Dict[str, Any]],
        intelligence_result: Dict[str, Any],
        memory_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Detect repeat IOC or entity activity."""

        repeated_entities: Dict[str, List[str]] = {
            "ips": [],
            "domains": [],
            "hashes": [],
            "hostnames": [],
            "usernames": [],
            "mitre_ids": [],
        }

        for match in direct_matches:
            overlap = match.get(
                "overlap",
                {},
            )

            if not isinstance(overlap, dict):
                continue

            for entity_type in repeated_entities:
                repeated_entities[entity_type].extend(
                    self._flatten_values(
                        overlap.get(
                            entity_type,
                            [],
                        )
                    )
                )

        for entity_type in repeated_entities:
            repeated_entities[entity_type] = (
                self._deduplicate(
                    repeated_entities[entity_type]
                )
            )

        repeat_flags = self._extract_recursive_values(
            {
                "intelligence": intelligence_result,
                "memory": memory_result,
            },
            {
                "is_repeat_offender",
                "repeat_offender",
                "is_repeated",
            },
        )

        external_repeat_flag = any(
            value is True
            or str(value).strip().lower()
            in {
                "true",
                "yes",
                "1",
            }
            for value in repeat_flags
        )

        repeated_count = sum(
            len(values)
            for values in repeated_entities.values()
        )

        is_repeat_offender = (
            external_repeat_flag
            or repeated_count > 0
        )

        return {
            "is_repeat_offender": (
                is_repeat_offender
            ),
            "repeated_entities": repeated_entities,
            "repeated_entity_count": repeated_count,
            "current_entity_count": sum(
                len(values)
                for values in entities.values()
            ),
        }

    def _calculate_correlation_score(
        self,
        direct_matches: List[Dict[str, Any]],
        related_incident_ids: List[str],
        repeat_analysis: Dict[str, Any],
        intelligence_result: Dict[str, Any],
        memory_result: Dict[str, Any],
    ) -> int:
        """Calculate deterministic historical-correlation score."""

        score = 0

        if direct_matches:
            highest_match = max(
                match.get(
                    "match_score",
                    0,
                )
                for match in direct_matches
            )

            score += min(
                int(highest_match),
                45,
            )

        score += min(
            len(related_incident_ids) * 10,
            25,
        )

        if repeat_analysis[
            "is_repeat_offender"
        ]:
            score += 20

        score += min(
            int(
                repeat_analysis[
                    "repeated_entity_count"
                ]
            )
            * 5,
            15,
        )

        external_scores = (
            self._extract_recursive_values(
                {
                    "intelligence": intelligence_result,
                    "memory": memory_result,
                },
                {
                    "correlation_score",
                    "similarity_score",
                    "highest_similarity_score",
                    "match_score",
                },
            )
        )

        numeric_external_scores: List[float] = []

        for value in external_scores:
            try:
                numeric_value = float(value)

                if 0 <= numeric_value <= 1:
                    numeric_value *= 100

                numeric_external_scores.append(
                    numeric_value
                )

            except (TypeError, ValueError):
                continue

        if numeric_external_scores:
            score = max(
                score,
                int(
                    max(numeric_external_scores)
                ),
            )

        return min(max(score, 0), 100)

    @staticmethod
    def _match_level(score: int) -> str:
        """Convert correlation score into match level."""

        if score >= 85:
            return "CRITICAL"

        if score >= 65:
            return "HIGH"

        if score >= 40:
            return "MEDIUM"

        if score >= 20:
            return "LOW"

        return "NONE"

    @staticmethod
    def _priority_from_score(
        score: int,
    ) -> TaskPriority:
        """Convert correlation score into task priority."""

        if score >= 85:
            return TaskPriority.P1

        if score >= 65:
            return TaskPriority.P2

        if score >= 40:
            return TaskPriority.P3

        return TaskPriority.P4

    @staticmethod
    def _confidence_from_score(
        score: int,
        related_incident_count: int,
    ) -> float:
        """Calculate deterministic correlation confidence."""

        if score >= 85:
            confidence = 0.95
        elif score >= 65:
            confidence = 0.88
        elif score >= 40:
            confidence = 0.78
        elif score >= 20:
            confidence = 0.65
        else:
            confidence = 0.45

        if related_incident_count >= 2:
            confidence += 0.03

        return min(
            round(confidence, 2),
            0.98,
        )

    def _build_follow_up_tasks(
        self,
        task: InvestigationTask,
        correlation_summary: Dict[str, Any],
    ) -> List[InvestigationTask]:
        """Build tasks that depend on historical correlation."""

        if (
            correlation_summary["match_level"]
            == "NONE"
        ):
            return []

        priority = self._priority_from_score(
            correlation_summary[
                "correlation_score"
            ]
        )

        compact_result = {
            "correlation_score": (
                correlation_summary[
                    "correlation_score"
                ]
            ),
            "match_level": (
                correlation_summary[
                    "match_level"
                ]
            ),
            "is_repeat_offender": (
                correlation_summary[
                    "is_repeat_offender"
                ]
            ),
            "related_incident_ids": (
                correlation_summary[
                    "related_incident_ids"
                ]
            ),
            "repeated_entities": (
                correlation_summary[
                    "repeated_entities"
                ]
            ),
        }

        return [
            InvestigationTask(
                task_type="root_cause_analysis",
                assigned_agent="root_cause_agent",
                description=(
                    "Use historical correlations and repeated "
                    "entities to reconstruct the likely attack chain."
                ),
                priority=priority,
                input_data={
                    "historical_correlation": (
                        compact_result
                    )
                },
                dependencies=[task.task_id],
            ),
            InvestigationTask(
                task_type="response_recommendation",
                assigned_agent=(
                    "response_advisor_agent"
                ),
                description=(
                    "Use repeat-offender and historical incident "
                    "evidence to recommend response actions."
                ),
                priority=priority,
                input_data={
                    "historical_correlation": (
                        compact_result
                    )
                },
                dependencies=[task.task_id],
            ),
        ]

    def execute_task(
        self,
        task: InvestigationTask,
    ) -> AgentExecutionResult:
        """Execute historical incident correlation."""

        entities = self._collect_current_entities(
            task
        )

        payload = self._build_correlation_payload(
            entities
        )

        component_configuration = dict(
            self.configuration
        )

        intelligence_correlator = (
            self._instantiate_component(
                IntelligenceCorrelator,
                component_configuration,
            )
        )

        memory_correlation_engine = (
            self._instantiate_component(
                CorrelationEngine,
                component_configuration,
            )
        )

        incident_store = self._instantiate_component(
            IncidentStore,
            component_configuration,
        )

        timeline = self._instantiate_component(
            IncidentTimeline,
            component_configuration,
        )

        intelligence_result = (
            self._run_intelligence_correlation(
                correlator=intelligence_correlator,
                payload=payload,
                entities=entities,
            )
        )

        memory_result = self._run_memory_correlation(
            correlation_engine=(
                memory_correlation_engine
            ),
            payload=payload,
        )

        incident_history = (
            self._load_incident_history(
                incident_store
            )
        )

        direct_matches = (
            self._find_direct_history_matches(
                incidents=incident_history,
                entities=entities,
                current_incident_id=(
                    self.context.investigation.incident_id
                ),
            )
        )

        timeline_result = self._to_dict(
            self._call_first_available(
                timeline,
                [
                    "build",
                    "build_timeline",
                    "get_timeline",
                    "generate_timeline",
                    "analyze",
                ],
                [
                    (entities,),
                    (payload,),
                    tuple(),
                ],
            )
        )

        related_incident_ids = (
            self._extract_related_incident_ids(
                intelligence_result,
                memory_result,
                direct_matches,
                timeline_result,
            )
        )

        repeat_analysis = (
            self._detect_repeat_offender(
                entities=entities,
                direct_matches=direct_matches,
                intelligence_result=(
                    intelligence_result
                ),
                memory_result=memory_result,
            )
        )

        correlation_score = (
            self._calculate_correlation_score(
                direct_matches=direct_matches,
                related_incident_ids=(
                    related_incident_ids
                ),
                repeat_analysis=repeat_analysis,
                intelligence_result=(
                    intelligence_result
                ),
                memory_result=memory_result,
            )
        )

        match_level = self._match_level(
            correlation_score
        )

        investigation_priority = (
            self._priority_from_score(
                correlation_score
            )
        )

        confidence = self._confidence_from_score(
            score=correlation_score,
            related_incident_count=len(
                related_incident_ids
            ),
        )

        if match_level == "CRITICAL":
            recommended_action = (
                "escalate_and_contain"
            )
        elif match_level == "HIGH":
            recommended_action = (
                "escalate_and_investigate"
            )
        elif match_level == "MEDIUM":
            recommended_action = (
                "investigate_and_monitor"
            )
        else:
            recommended_action = "monitor"

        correlation_summary = {
            "correlation_score": correlation_score,
            "match_level": match_level,
            "investigation_priority": (
                investigation_priority.value
            ),
            "recommended_action": (
                recommended_action
            ),
            "is_repeat_offender": (
                repeat_analysis[
                    "is_repeat_offender"
                ]
            ),
            "repeated_entities": (
                repeat_analysis[
                    "repeated_entities"
                ]
            ),
            "repeated_entity_count": (
                repeat_analysis[
                    "repeated_entity_count"
                ]
            ),
            "related_incident_ids": (
                related_incident_ids
            ),
            "related_incident_count": len(
                related_incident_ids
            ),
            "direct_matches": direct_matches,
            "current_entities": entities,
            "confidence": confidence,
            "component_results": {
                "intelligence_correlator": (
                    intelligence_result
                ),
                "memory_correlation_engine": (
                    memory_result
                ),
                "timeline": timeline_result,
            },
        }

        if repeat_analysis["is_repeat_offender"]:
            summary = (
                f"Historical correlation identified repeat-offender "
                f"activity with a correlation score of "
                f"{correlation_score}/100 and {match_level} match "
                f"level. {len(related_incident_ids)} related "
                f"incident(s) were identified."
            )
        elif related_incident_ids:
            summary = (
                f"Historical correlation identified "
                f"{len(related_incident_ids)} related incident(s) "
                f"with a correlation score of "
                f"{correlation_score}/100 and {match_level} match "
                f"level."
            )
        else:
            summary = (
                "Historical correlation found no confirmed prior "
                "incident relationship or repeat-offender activity. "
                f"Correlation score: {correlation_score}/100."
            )

        evidence: List[Evidence] = []

        for match in direct_matches:
            evidence.append(
                Evidence(
                    evidence_type=(
                        EvidenceType.HISTORICAL_INCIDENT
                    ),
                    source=self.agent_name,
                    value=match,
                    description=(
                        "Historical incident matched current "
                        "investigation entities."
                    ),
                    confidence=confidence,
                    tags=[
                        "historical_correlation",
                        "related_incident",
                        match_level.lower(),
                    ],
                )
            )

        if repeat_analysis["is_repeat_offender"]:
            evidence.append(
                Evidence(
                    evidence_type=(
                        EvidenceType.AGENT_FINDING
                    ),
                    source=self.agent_name,
                    value={
                        "is_repeat_offender": True,
                        "repeated_entities": (
                            repeat_analysis[
                                "repeated_entities"
                            ]
                        ),
                        "related_incident_ids": (
                            related_incident_ids
                        ),
                    },
                    description=(
                        "Repeated indicators or entities were "
                        "identified across historical incidents."
                    ),
                    confidence=confidence,
                    tags=[
                        "repeat_offender",
                        "historical_correlation",
                        match_level.lower(),
                    ],
                )
            )

        evidence.append(
            Evidence(
                evidence_type=(
                    EvidenceType.AGENT_FINDING
                ),
                source=self.agent_name,
                value={
                    "correlation_score": (
                        correlation_score
                    ),
                    "match_level": match_level,
                    "investigation_priority": (
                        investigation_priority.value
                    ),
                    "recommended_action": (
                        recommended_action
                    ),
                },
                description=(
                    "Deterministic historical correlation "
                    "assessment."
                ),
                confidence=confidence,
                tags=[
                    "correlation_score",
                    "historical_analysis",
                    match_level.lower(),
                ],
            )
        )

        finding = AgentFinding(
            agent_name=self.agent_name,
            title="Historical Incident Correlation",
            summary=summary,
            severity=(
                "CRITICAL"
                if match_level == "CRITICAL"
                else "HIGH"
                if match_level == "HIGH"
                else "MEDIUM"
                if match_level == "MEDIUM"
                else "LOW"
            ),
            confidence=confidence,
            evidence_ids=[
                item.evidence_id
                for item in evidence
            ],
            recommendations=[
                (
                    "Review all related historical incidents and "
                    "their response outcomes."
                ),
                (
                    "Prioritize repeated indicators for containment "
                    "review when supported by threat intelligence."
                ),
                (
                    "Use recurring ATT&CK techniques to reconstruct "
                    "the broader attack campaign."
                ),
                (
                    "Escalate repeat-offender activity to the "
                    "response orchestration layer."
                ),
            ],
            metadata=correlation_summary,
        )

        hypotheses: List[
            InvestigationHypothesis
        ] = []

        if repeat_analysis["is_repeat_offender"]:
            hypotheses.append(
                InvestigationHypothesis(
                    title=(
                        "Recurring malicious actor or infrastructure"
                    ),
                    description=(
                        "Repeated indicators or entities across "
                        "multiple incidents suggest recurring "
                        "malicious infrastructure, tooling, or actor "
                        "activity."
                    ),
                    proposed_by=self.agent_name,
                    confidence=confidence,
                    supporting_evidence_ids=[
                        item.evidence_id
                        for item in evidence
                    ],
                    required_evidence=[
                        (
                            "Root-cause reconstruction across related "
                            "incidents"
                        ),
                        (
                            "Threat-intelligence confirmation for "
                            "repeated observables"
                        ),
                        (
                            "Comparison of ATT&CK techniques and "
                            "affected assets"
                        ),
                    ],
                    metadata={
                        "correlation_score": (
                            correlation_score
                        ),
                        "related_incident_ids": (
                            related_incident_ids
                        ),
                        "repeated_entities": (
                            repeat_analysis[
                                "repeated_entities"
                            ]
                        ),
                    },
                )
            )

        self.set_shared_value(
            key="historical_correlation",
            value=correlation_summary,
        )

        self.send_message(
            recipient_agent="root_cause_agent",
            subject=(
                "Historical correlation analysis ready"
            ),
            content=summary,
            message_type="correlation_result",
            related_task_id=task.task_id,
            related_evidence_ids=[
                item.evidence_id
                for item in evidence
            ],
            metadata={
                "correlation_score": (
                    correlation_score
                ),
                "match_level": match_level,
                "is_repeat_offender": (
                    repeat_analysis[
                        "is_repeat_offender"
                    ]
                ),
                "related_incident_ids": (
                    related_incident_ids
                ),
            },
        )

        self.send_message(
            recipient_agent=(
                "response_advisor_agent"
            ),
            subject=(
                "Correlation evidence ready for response planning"
            ),
            content=summary,
            message_type="correlation_result",
            related_task_id=task.task_id,
            related_evidence_ids=[
                item.evidence_id
                for item in evidence
            ],
            metadata={
                "correlation_score": (
                    correlation_score
                ),
                "match_level": match_level,
                "recommended_action": (
                    recommended_action
                ),
                "is_repeat_offender": (
                    repeat_analysis[
                        "is_repeat_offender"
                    ]
                ),
            },
        )

        proposed_tasks = self._build_follow_up_tasks(
            task=task,
            correlation_summary=(
                correlation_summary
            ),
        )

        return self.create_success_result(
            summary=summary,
            findings=[finding],
            evidence=evidence,
            proposed_tasks=proposed_tasks,
            proposed_hypotheses=hypotheses,
            metadata=correlation_summary,
        )