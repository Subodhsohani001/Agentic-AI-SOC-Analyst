from __future__ import annotations

from typing import Any, Dict, List, Set

from ..agent_base import BaseInvestigationAgent
from ..investigation_models import (
    AgentExecutionResult,
    AgentFinding,
    Evidence,
    EvidenceType,
    InvestigationTask,
    TaskPriority,
)


class ResponseAdvisorAgent(BaseInvestigationAgent):
    """
    Produces evidence-based response recommendations.

    This agent does not execute containment actions directly. It prepares
    recommended actions for the existing response_engine, where policy,
    approval, simulation, execution, and audit logging are handled.
    """

    agent_name = "response_advisor_agent"
    description = (
        "Recommends prioritized containment, investigation, recovery, "
        "and monitoring actions using shared investigation evidence."
    )
    version = "0.7.0"

    SEVERITY_ORDER = {
        "INFORMATIONAL": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    @property
    def supported_task_types(self) -> Set[str]:
        return {
            "response_recommendation",
            "response_advice",
            "containment_recommendation",
            "remediation_planning",
        }

    @staticmethod
    def _safe_dict(value: Any) -> Dict[str, Any]:
        """Return a dictionary or an empty dictionary."""

        return value if isinstance(value, dict) else {}

    @staticmethod
    def _flatten_values(value: Any) -> List[str]:
        """Flatten nested values into strings."""

        values: List[str] = []

        if value is None:
            return values

        if isinstance(value, str):
            normalized = value.strip()

            if normalized:
                values.append(normalized)

            return values

        if isinstance(value, dict):
            for nested_value in value.values():
                values.extend(
                    ResponseAdvisorAgent._flatten_values(
                        nested_value
                    )
                )

            return values

        if isinstance(value, (list, tuple, set)):
            for item in value:
                values.extend(
                    ResponseAdvisorAgent._flatten_values(item)
                )

            return values

        values.append(str(value).strip())

        return values

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

    def _collect_sources(
        self,
        task: InvestigationTask,
    ) -> Dict[str, Any]:
        """Collect all relevant shared investigation outputs."""

        return {
            "task_input": dict(task.input_data or {}),
            "triage": self._safe_dict(
                self.get_shared_value(
                    "triage_assessment",
                    {},
                )
            ),
            "iocs": self._safe_dict(
                self.get_shared_value(
                    "normalized_iocs",
                    {},
                )
            ),
            "mitre": self._safe_dict(
                self.get_shared_value(
                    "mitre_attack_mapping",
                    {},
                )
            ),
            "threat_intelligence": self._safe_dict(
                self.get_shared_value(
                    "threat_intelligence_results",
                    {},
                )
            ),
            "correlation": self._safe_dict(
                self.get_shared_value(
                    "historical_correlation",
                    {},
                )
            ),
            "root_cause": self._safe_dict(
                self.get_shared_value(
                    "root_cause_assessment",
                    {},
                )
            ),
        }

    def _determine_severity(
        self,
        sources: Dict[str, Any],
    ) -> str:
        """Determine the highest supported severity."""

        candidates = [
            str(
                self.context.investigation.severity
            ).upper(),
            str(
                sources["triage"].get(
                    "assessed_severity",
                    "",
                )
            ).upper(),
            str(
                sources["root_cause"].get(
                    "severity",
                    "",
                )
            ).upper(),
            str(
                sources["threat_intelligence"]
                .get(
                    "summary",
                    {},
                )
                .get(
                    "highest_severity",
                    "",
                )
                if isinstance(
                    sources["threat_intelligence"].get(
                        "summary",
                        {},
                    ),
                    dict,
                )
                else ""
            ).upper(),
            str(
                sources["correlation"].get(
                    "match_level",
                    "",
                )
            ).upper(),
        ]

        valid_candidates = [
            value
            for value in candidates
            if value in self.SEVERITY_ORDER
        ]

        if not valid_candidates:
            return "LOW"

        return max(
            valid_candidates,
            key=lambda value: self.SEVERITY_ORDER[
                value
            ],
        )

    def _collect_entities(
        self,
        sources: Dict[str, Any],
    ) -> Dict[str, List[str]]:
        """Collect response targets from shared evidence."""

        normalized_iocs = sources["iocs"].get(
            "normalized",
            sources["iocs"],
        )

        if not isinstance(normalized_iocs, dict):
            normalized_iocs = {}

        repeated_entities = sources[
            "correlation"
        ].get(
            "repeated_entities",
            {},
        )

        if not isinstance(repeated_entities, dict):
            repeated_entities = {}

        ips = self._deduplicate(
            self._flatten_values(
                normalized_iocs.get("ips", [])
            )
            + self._flatten_values(
                sources["triage"].get(
                    "source_ips",
                    [],
                )
            )
            + self._flatten_values(
                repeated_entities.get(
                    "ips",
                    [],
                )
            )
        )

        domains = self._deduplicate(
            self._flatten_values(
                normalized_iocs.get(
                    "domains",
                    [],
                )
            )
            + self._flatten_values(
                repeated_entities.get(
                    "domains",
                    [],
                )
            )
        )

        hashes = self._deduplicate(
            self._flatten_values(
                normalized_iocs.get(
                    "hashes",
                    [],
                )
            )
            + self._flatten_values(
                repeated_entities.get(
                    "hashes",
                    [],
                )
            )
        )

        hostnames = self._deduplicate(
            self._flatten_values(
                sources["triage"].get(
                    "hostnames",
                    [],
                )
            )
            + self._flatten_values(
                sources["task_input"].get(
                    "hostnames",
                    sources["task_input"].get(
                        "hostname",
                        [],
                    ),
                )
            )
            + self._flatten_values(
                repeated_entities.get(
                    "hostnames",
                    [],
                )
            )
        )

        usernames = self._deduplicate(
            self._flatten_values(
                sources["triage"].get(
                    "usernames",
                    [],
                )
            )
            + self._flatten_values(
                sources["task_input"].get(
                    "usernames",
                    sources["task_input"].get(
                        "username",
                        [],
                    ),
                )
            )
            + self._flatten_values(
                repeated_entities.get(
                    "usernames",
                    [],
                )
            )
        )

        return {
            "ips": ips,
            "domains": domains,
            "hashes": hashes,
            "hostnames": hostnames,
            "usernames": usernames,
        }

    def _collect_malicious_observables(
        self,
        sources: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Return observables supported as malicious or suspicious."""

        observables = sources[
            "threat_intelligence"
        ].get(
            "observables",
            [],
        )

        if not isinstance(observables, list):
            observables = []

        results: List[Dict[str, Any]] = []

        for record in observables:
            if not isinstance(record, dict):
                continue

            verdict = str(
                record.get(
                    "verdict",
                    "unknown",
                )
            ).lower()

            if verdict not in {
                "confirmed_malicious",
                "malicious",
                "suspicious",
            }:
                continue

            results.append(
                {
                    "observable": record.get(
                        "observable"
                    ),
                    "observable_type": record.get(
                        "observable_type"
                    ),
                    "verdict": verdict,
                    "risk_score": int(
                        record.get(
                            "risk_score",
                            0,
                        )
                        or 0
                    ),
                    "severity": str(
                        record.get(
                            "severity",
                            "UNKNOWN",
                        )
                    ).upper(),
                    "confidence": float(
                        record.get(
                            "confidence",
                            0.50,
                        )
                        or 0.50
                    ),
                }
            )

        return results

    @staticmethod
    def _action(
        action_type: str,
        target: str,
        reason: str,
        priority: str,
        requires_approval: bool,
        phase: str,
        metadata: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Build a normalized response recommendation."""

        return {
            "action_type": action_type,
            "target": target,
            "reason": reason,
            "priority": priority,
            "requires_approval": requires_approval,
            "phase": phase,
            "metadata": metadata or {},
        }

    def _build_actions(
        self,
        severity: str,
        entities: Dict[str, List[str]],
        malicious_observables: List[Dict[str, Any]],
        sources: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Build deterministic response recommendations."""

        actions: List[Dict[str, Any]] = []

        correlation = sources["correlation"]
        root_cause = sources["root_cause"]

        is_repeat_offender = bool(
            correlation.get(
                "is_repeat_offender",
                False,
            )
        )

        match_level = str(
            correlation.get(
                "match_level",
                "NONE",
            )
        ).upper()

        attack_chain = root_cause.get(
            "attack_chain_stages",
            [],
        )

        if not isinstance(attack_chain, list):
            attack_chain = []

        actions.append(
            self._action(
                action_type="create_ticket",
                target=(
                    self.context.investigation.incident_id
                ),
                reason=(
                    "Track investigation findings, evidence, "
                    "decisions, and response progress."
                ),
                priority=(
                    "P1"
                    if severity == "CRITICAL"
                    else "P2"
                ),
                requires_approval=False,
                phase="coordination",
            )
        )

        actions.append(
            self._action(
                action_type="notify_soc",
                target="SOC channel",
                reason=(
                    f"Share the {severity} investigation outcome "
                    "with analysts and incident responders."
                ),
                priority=(
                    "P1"
                    if severity in {
                        "CRITICAL",
                        "HIGH",
                    }
                    else "P2"
                ),
                requires_approval=False,
                phase="coordination",
            )
        )

        for hostname in entities["hostnames"]:
            actions.append(
                self._action(
                    action_type="collect_forensics",
                    target=hostname,
                    reason=(
                        "Preserve volatile and persistent endpoint "
                        "evidence before containment or remediation."
                    ),
                    priority=(
                        "P1"
                        if severity == "CRITICAL"
                        else "P2"
                    ),
                    requires_approval=False,
                    phase="evidence_preservation",
                    metadata={
                        "recommended_artifacts": [
                            "process tree",
                            "command-line history",
                            "network connections",
                            "PowerShell logs",
                            "authentication logs",
                            "memory capture",
                        ]
                    },
                )
            )

        blockable_ips: List[str] = []

        for record in malicious_observables:
            if (
                record.get(
                    "observable_type"
                )
                == "ip"
                and record.get(
                    "verdict"
                )
                in {
                    "confirmed_malicious",
                    "malicious",
                }
                and float(
                    record.get(
                        "confidence",
                        0,
                    )
                )
                >= 0.75
            ):
                observable = str(
                    record.get(
                        "observable",
                        "",
                    )
                ).strip()

                if observable:
                    blockable_ips.append(
                        observable
                    )

        if is_repeat_offender:
            blockable_ips.extend(
                entities["ips"]
            )

        for ip_address in self._deduplicate(
            blockable_ips
        ):
            actions.append(
                self._action(
                    action_type="block_ip",
                    target=ip_address,
                    reason=(
                        "The IP is supported by malicious "
                        "threat-intelligence or repeat-offender "
                        "correlation evidence."
                    ),
                    priority=(
                        "P1"
                        if severity == "CRITICAL"
                        or match_level == "CRITICAL"
                        else "P2"
                    ),
                    requires_approval=True,
                    phase="containment",
                    metadata={
                        "is_repeat_offender": (
                            is_repeat_offender
                        ),
                        "match_level": match_level,
                    },
                )
            )

        should_isolate_hosts = (
            severity == "CRITICAL"
            or any(
                stage in attack_chain
                for stage in {
                    "Credential Access",
                    "Lateral Movement",
                    "Exfiltration",
                    "Impact",
                }
            )
        )

        if should_isolate_hosts:
            for hostname in entities["hostnames"]:
                actions.append(
                    self._action(
                        action_type="isolate_host",
                        target=hostname,
                        reason=(
                            "Reduce attacker access while preserving "
                            "the system for investigation."
                        ),
                        priority="P1",
                        requires_approval=True,
                        phase="containment",
                    )
                )

        credential_activity = any(
            stage in attack_chain
            for stage in {
                "Credential Access",
                "Lateral Movement",
            }
        )

        if credential_activity:
            for username in entities["usernames"]:
                actions.append(
                    self._action(
                        action_type="disable_user",
                        target=username,
                        reason=(
                            "Credential-access or lateral-movement "
                            "evidence indicates possible account "
                            "compromise."
                        ),
                        priority="P1",
                        requires_approval=True,
                        phase="containment",
                    )
                )

                actions.append(
                    self._action(
                        action_type="reset_credentials",
                        target=username,
                        reason=(
                            "Rotate credentials after account "
                            "compromise has been investigated."
                        ),
                        priority="P1",
                        requires_approval=True,
                        phase="eradication",
                    )
                )

        if entities["domains"]:
            for domain in entities["domains"]:
                actions.append(
                    self._action(
                        action_type="block_domain",
                        target=domain,
                        reason=(
                            "Prevent access to suspicious or "
                            "malicious infrastructure supported by "
                            "incident evidence."
                        ),
                        priority=(
                            "P1"
                            if severity == "CRITICAL"
                            else "P2"
                        ),
                        requires_approval=True,
                        phase="containment",
                    )
                )

        actions.append(
            self._action(
                action_type="increase_monitoring",
                target="affected environment",
                reason=(
                    "Detect repeated indicators, related ATT&CK "
                    "techniques, and post-containment activity."
                ),
                priority=(
                    "P1"
                    if severity in {
                        "CRITICAL",
                        "HIGH",
                    }
                    else "P2"
                ),
                requires_approval=False,
                phase="monitoring",
                metadata={
                    "mitre_ids": sources[
                        "mitre"
                    ].get(
                        "technique_ids",
                        [],
                    )
                },
            )
        )

        actions.append(
            self._action(
                action_type="validate_remediation",
                target="affected environment",
                reason=(
                    "Confirm that malicious processes, persistence, "
                    "communications, and compromised access paths "
                    "have been removed."
                ),
                priority=(
                    "P1"
                    if severity == "CRITICAL"
                    else "P2"
                ),
                requires_approval=False,
                phase="recovery",
            )
        )

        return actions

    @staticmethod
    def _deduplicate_actions(
        actions: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Deduplicate recommendations by action type and target."""

        seen: Set[tuple[str, str]] = set()
        results: List[Dict[str, Any]] = []

        for action in actions:
            key = (
                str(
                    action.get(
                        "action_type",
                        "",
                    )
                ),
                str(
                    action.get(
                        "target",
                        "",
                    )
                ),
            )

            if key in seen:
                continue

            seen.add(key)
            results.append(action)

        priority_order = {
            "P1": 1,
            "P2": 2,
            "P3": 3,
            "P4": 4,
        }

        phase_order = {
            "coordination": 1,
            "evidence_preservation": 2,
            "containment": 3,
            "eradication": 4,
            "monitoring": 5,
            "recovery": 6,
        }

        return sorted(
            results,
            key=lambda action: (
                priority_order.get(
                    action["priority"],
                    99,
                ),
                phase_order.get(
                    action["phase"],
                    99,
                ),
                action["action_type"],
                action["target"],
            ),
        )

    @staticmethod
    def _determine_recommended_mode(
        severity: str,
        actions: List[Dict[str, Any]],
    ) -> str:
        """Determine how aggressively actions should be handled."""

        approval_action_count = sum(
            1
            for action in actions
            if action["requires_approval"]
        )

        if (
            severity == "CRITICAL"
            and approval_action_count > 0
        ):
            return "human_approved_response"

        if severity in {
            "HIGH",
            "MEDIUM",
        }:
            return "analyst_review_required"

        return "monitoring_only"

    @staticmethod
    def _calculate_confidence(
        sources: Dict[str, Any],
        malicious_observables: List[Dict[str, Any]],
    ) -> float:
        """Calculate response-advice confidence."""

        confidence_values: List[float] = []

        for source_name in (
            "triage",
            "correlation",
            "root_cause",
        ):
            source = sources[source_name]

            for key in (
                "confidence",
                "overall_confidence",
                "root_cause_confidence",
            ):
                value = source.get(key)

                if isinstance(value, (int, float)):
                    confidence_values.append(
                        float(value)
                    )

        confidence_values.extend(
            float(
                record.get(
                    "confidence",
                    0.50,
                )
            )
            for record
            in malicious_observables
        )

        if not confidence_values:
            return 0.55

        return min(
            max(
                round(
                    sum(confidence_values)
                    / len(confidence_values),
                    2,
                ),
                0.40,
            ),
            0.98,
        )

    def execute_task(
        self,
        task: InvestigationTask,
    ) -> AgentExecutionResult:
        """Produce prioritized response recommendations."""

        sources = self._collect_sources(task)

        task_root_cause = sources[
            "task_input"
        ].get(
            "root_cause_assessment",
            {},
        )

        if (
            not sources["root_cause"]
            and isinstance(
                task_root_cause,
                dict,
            )
        ):
            sources["root_cause"] = (
                task_root_cause
            )

        severity = self._determine_severity(
            sources
        )

        entities = self._collect_entities(
            sources
        )

        malicious_observables = (
            self._collect_malicious_observables(
                sources
            )
        )

        actions = self._deduplicate_actions(
            self._build_actions(
                severity=severity,
                entities=entities,
                malicious_observables=(
                    malicious_observables
                ),
                sources=sources,
            )
        )

        requires_approval_count = sum(
            1
            for action in actions
            if action["requires_approval"]
        )

        immediate_action_count = sum(
            1
            for action in actions
            if action["priority"] == "P1"
        )

        recommended_mode = (
            self._determine_recommended_mode(
                severity=severity,
                actions=actions,
            )
        )

        confidence = self._calculate_confidence(
            sources=sources,
            malicious_observables=(
                malicious_observables
            ),
        )

        response_plan = {
            "severity": severity,
            "confidence": confidence,
            "recommended_mode": (
                recommended_mode
            ),
            "actions": actions,
            "action_count": len(actions),
            "immediate_action_count": (
                immediate_action_count
            ),
            "requires_approval_count": (
                requires_approval_count
            ),
            "entities": entities,
            "malicious_observables": (
                malicious_observables
            ),
            "root_cause": sources[
                "root_cause"
            ].get(
                "primary_root_cause"
            ),
            "attack_chain_stages": sources[
                "root_cause"
            ].get(
                "attack_chain_stages",
                [],
            ),
            "is_repeat_offender": sources[
                "correlation"
            ].get(
                "is_repeat_offender",
                False,
            ),
            "correlation_score": sources[
                "correlation"
            ].get(
                "correlation_score",
                0,
            ),
        }

        summary = (
            f"Response advisory produced {len(actions)} action "
            f"recommendation(s) for a {severity} incident. "
            f"{immediate_action_count} action(s) are P1 and "
            f"{requires_approval_count} action(s) require human "
            f"approval. Recommended operating mode: "
            f"{recommended_mode}."
        )

        evidence = [
            Evidence(
                evidence_type=(
                    EvidenceType.AGENT_FINDING
                ),
                source=self.agent_name,
                value=response_plan,
                description=(
                    "Evidence-based response recommendation plan."
                ),
                confidence=confidence,
                tags=[
                    "response_advice",
                    "containment",
                    severity.lower(),
                    recommended_mode,
                ],
            )
        ]

        finding = AgentFinding(
            agent_name=self.agent_name,
            title="Response Recommendation Plan",
            summary=summary,
            severity=severity,
            confidence=confidence,
            evidence_ids=[
                item.evidence_id
                for item in evidence
            ],
            recommendations=[
                (
                    f"{action['action_type']} "
                    f"{action['target']}: "
                    f"{action['reason']}"
                )
                for action in actions
            ],
            metadata=response_plan,
        )

        self.set_shared_value(
            key="response_advisory",
            value=response_plan,
        )

        self.send_message(
            recipient_agent="coordinator",
            subject="Response advisory completed",
            content=summary,
            message_type="response_advisory_result",
            related_task_id=task.task_id,
            related_evidence_ids=[
                item.evidence_id
                for item in evidence
            ],
            metadata={
                "severity": severity,
                "recommended_mode": (
                    recommended_mode
                ),
                "action_count": len(actions),
                "requires_approval_count": (
                    requires_approval_count
                ),
            },
        )

        return self.create_success_result(
            summary=summary,
            findings=[finding],
            evidence=evidence,
            metadata=response_plan,
        )