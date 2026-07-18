from __future__ import annotations

from typing import Any, Dict, List, Optional

from .evidence_manager import EvidenceManager
from .hypothesis_engine import HypothesisEngine
from .investigation_models import (
    HypothesisStatus,
    InvestigationStatus,
    TaskStatus,
    utc_now,
)
from .shared_context import SharedInvestigationContext


class InvestigationReporterError(Exception):
    """Raised when an investigation report cannot be generated."""


class InvestigationReporter:
    """
    Builds deterministic analyst-facing investigation reports.

    Responsibilities:
    - Summarize investigation lifecycle and task execution
    - Include specialist-agent findings
    - Include evidence integrity and evidence chain
    - Include hypothesis ranking and final assessment
    - Include IOC, MITRE, threat-intelligence, and correlation results
    - Include reconstructed attack chain and root cause
    - Include response recommendations
    - Produce a JSON-serializable report structure
    """

    def __init__(
        self,
        context: SharedInvestigationContext,
        configuration: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not isinstance(context, SharedInvestigationContext):
            raise TypeError(
                "context must be a SharedInvestigationContext instance."
            )

        self.context = context
        self.configuration = configuration or {}

        self.evidence_manager = EvidenceManager(
            context=context,
            configuration=self.configuration.get(
                "evidence_manager",
                {},
            ),
        )

        self.hypothesis_engine = HypothesisEngine(
            context=context,
            configuration=self.configuration.get(
                "hypothesis_engine",
                {},
            ),
        )

    @staticmethod
    def _safe_dict(value: Any) -> Dict[str, Any]:
        """Return a dictionary or an empty dictionary."""

        return value if isinstance(value, dict) else {}

    @staticmethod
    def _safe_list(value: Any) -> List[Any]:
        """Return a list or an empty list."""

        return value if isinstance(value, list) else []

    @staticmethod
    def _severity_rank(severity: str) -> int:
        """Return deterministic severity ordering."""

        return {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFORMATIONAL": 1,
            "UNKNOWN": 0,
        }.get(
            str(severity).upper(),
            0,
        )

    def _build_executive_summary(
        self,
        shared_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build the report's executive summary."""

        investigation = self.context.investigation

        triage = shared_results["triage"]
        threat_intelligence = shared_results[
            "threat_intelligence"
        ]
        correlation = shared_results["correlation"]
        root_cause = shared_results["root_cause"]
        response = shared_results["response"]

        severity_candidates = [
            investigation.severity,
            triage.get(
                "assessed_severity",
                "UNKNOWN",
            ),
            self._safe_dict(
                threat_intelligence.get(
                    "summary",
                    {},
                )
            ).get(
                "highest_severity",
                "UNKNOWN",
            ),
            correlation.get(
                "match_level",
                "UNKNOWN",
            ),
            root_cause.get(
                "severity",
                "UNKNOWN",
            ),
            response.get(
                "severity",
                "UNKNOWN",
            ),
        ]

        highest_severity = max(
            severity_candidates,
            key=self._severity_rank,
        )

        threat_summary = self._safe_dict(
            threat_intelligence.get(
                "summary",
                {},
            )
        )

        malicious_count = int(
            threat_summary.get(
                "malicious_count",
                0,
            )
            or 0
        )

        suspicious_count = int(
            threat_summary.get(
                "suspicious_count",
                0,
            )
            or 0
        )

        correlation_score = int(
            correlation.get(
                "correlation_score",
                0,
            )
            or 0
        )

        is_repeat_offender = bool(
            correlation.get(
                "is_repeat_offender",
                False,
            )
        )

        primary_root_cause = root_cause.get(
            "primary_root_cause"
        )

        attack_chain_stages = self._safe_list(
            root_cause.get(
                "attack_chain_stages",
                [],
            )
        )

        action_count = int(
            response.get(
                "action_count",
                0,
            )
            or 0
        )

        approval_count = int(
            response.get(
                "requires_approval_count",
                0,
            )
            or 0
        )

        summary_parts = [
            (
                f"Investigation {investigation.investigation_id} "
                f"for incident {investigation.incident_id} "
                f"is currently {investigation.status.value}."
            ),
            (
                f"The highest supported severity is "
                f"{highest_severity}."
            ),
        ]

        if malicious_count or suspicious_count:
            summary_parts.append(
                f"Threat intelligence identified "
                f"{malicious_count} malicious and "
                f"{suspicious_count} suspicious observable(s)."
            )

        if correlation_score:
            summary_parts.append(
                f"Historical correlation score is "
                f"{correlation_score}/100."
            )

        if is_repeat_offender:
            summary_parts.append(
                "Repeat-offender activity was identified."
            )

        if primary_root_cause:
            summary_parts.append(
                f"The most probable root cause is: "
                f"{primary_root_cause}."
            )

        if attack_chain_stages:
            summary_parts.append(
                "The reconstructed attack chain is: "
                + " → ".join(
                    str(stage)
                    for stage in attack_chain_stages
                )
                + "."
            )

        if action_count:
            summary_parts.append(
                f"The response advisor recommended "
                f"{action_count} action(s), including "
                f"{approval_count} requiring human approval."
            )

        return {
            "summary": " ".join(summary_parts),
            "highest_severity": highest_severity,
            "investigation_status": (
                investigation.status.value
            ),
            "malicious_observable_count": malicious_count,
            "suspicious_observable_count": suspicious_count,
            "correlation_score": correlation_score,
            "is_repeat_offender": is_repeat_offender,
            "primary_root_cause": primary_root_cause,
            "attack_chain_stages": attack_chain_stages,
            "recommended_action_count": action_count,
            "approval_required_count": approval_count,
        }

    def _build_task_summary(self) -> Dict[str, Any]:
        """Build investigation task statistics."""

        tasks = list(
            self.context.investigation.tasks
        )

        status_counts = {
            status.value: sum(
                1
                for task in tasks
                if task.status == status
            )
            for status in TaskStatus
        }

        return {
            "task_count": len(tasks),
            "status_counts": status_counts,
            "tasks": [
                {
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "assigned_agent": (
                        task.assigned_agent
                    ),
                    "description": task.description,
                    "priority": task.priority.value,
                    "status": task.status.value,
                    "dependencies": list(
                        task.dependencies
                    ),
                    "result": task.result,
                    "error": task.error,
                    "created_at": task.created_at,
                    "started_at": task.started_at,
                    "completed_at": (
                        task.completed_at
                    ),
                }
                for task in tasks
            ],
        }

    def _build_agent_summary(self) -> Dict[str, Any]:
        """Build participating-agent statistics."""

        execution_results = (
            self.context.get_execution_results()
        )

        agent_names = sorted(
            set(
                self.context.investigation
                .participating_agents
            )
            | {
                result.agent_name
                for result in execution_results
            }
        )

        agents = []

        for agent_name in agent_names:
            results = [
                result
                for result in execution_results
                if result.agent_name == agent_name
            ]

            agents.append(
                {
                    "agent_name": agent_name,
                    "execution_count": len(results),
                    "successful_execution_count": sum(
                        1
                        for result in results
                        if result.success
                    ),
                    "failed_execution_count": sum(
                        1
                        for result in results
                        if not result.success
                    ),
                    "finding_count": sum(
                        len(result.findings)
                        for result in results
                    ),
                    "evidence_count": sum(
                        len(result.evidence)
                        for result in results
                    ),
                    "proposed_task_count": sum(
                        len(result.proposed_tasks)
                        for result in results
                    ),
                    "proposed_hypothesis_count": sum(
                        len(
                            result.proposed_hypotheses
                        )
                        for result in results
                    ),
                    "latest_summary": (
                        results[-1].summary
                        if results
                        else None
                    ),
                }
            )

        return {
            "participating_agent_count": len(
                agent_names
            ),
            "participating_agents": agent_names,
            "agents": agents,
        }

    def _build_findings_summary(self) -> Dict[str, Any]:
        """Build a normalized list of specialist findings."""

        findings = list(
            self.context.investigation.findings
        )

        severity_counts: Dict[str, int] = {}

        for finding in findings:
            severity = finding.severity.upper()

            severity_counts[severity] = (
                severity_counts.get(
                    severity,
                    0,
                )
                + 1
            )

        ordered_findings = sorted(
            findings,
            key=lambda finding: (
                -self._severity_rank(
                    finding.severity
                ),
                -finding.confidence,
                finding.created_at,
            ),
        )

        return {
            "finding_count": len(findings),
            "severity_counts": severity_counts,
            "findings": [
                finding.to_dict()
                for finding in ordered_findings
            ],
        }

    def _build_hypothesis_summary(
        self,
    ) -> Dict[str, Any]:
        """Build evaluated hypothesis information."""

        if not self.context.investigation.hypotheses:
            return {
                "hypothesis_count": 0,
                "leading_hypothesis": None,
                "status_counts": {
                    status.value: 0
                    for status in HypothesisStatus
                },
                "hypotheses": [],
            }

        assessment = (
            self.hypothesis_engine.build_assessment()
        )

        comparison = self._safe_dict(
            assessment.get(
                "comparison",
                {},
            )
        )

        return {
            "hypothesis_count": len(
                self.context.investigation
                .hypotheses
            ),
            "leading_hypothesis": (
                comparison.get(
                    "leading_hypothesis"
                )
            ),
            "status_counts": assessment.get(
                "status_counts",
                {},
            ),
            "ranked_hypotheses": comparison.get(
                "ranked_hypotheses",
                [],
            ),
            "confirmed_hypotheses": (
                assessment.get(
                    "confirmed_hypotheses",
                    [],
                )
            ),
            "rejected_hypotheses": (
                assessment.get(
                    "rejected_hypotheses",
                    [],
                )
            ),
            "hypotheses": [
                hypothesis.to_dict()
                for hypothesis
                in self.context.investigation.hypotheses
            ],
        }

    def _collect_shared_results(
        self,
    ) -> Dict[str, Any]:
        """Collect shared outputs from all framework components."""

        return {
            "triage": self._safe_dict(
                self.context.get_shared_value(
                    "triage_assessment",
                    {},
                )
            ),
            "iocs": self._safe_dict(
                self.context.get_shared_value(
                    "normalized_iocs",
                    {},
                )
            ),
            "mitre": self._safe_dict(
                self.context.get_shared_value(
                    "mitre_attack_mapping",
                    {},
                )
            ),
            "threat_intelligence": self._safe_dict(
                self.context.get_shared_value(
                    "threat_intelligence_results",
                    {},
                )
            ),
            "correlation": self._safe_dict(
                self.context.get_shared_value(
                    "historical_correlation",
                    {},
                )
            ),
            "root_cause": self._safe_dict(
                self.context.get_shared_value(
                    "root_cause_assessment",
                    {},
                )
            ),
            "attack_chain": self._safe_list(
                self.context.get_shared_value(
                    "attack_chain",
                    [],
                )
            ),
            "response": self._safe_dict(
                self.context.get_shared_value(
                    "response_advisory",
                    {},
                )
            ),
        }

    def _build_investigation_overview(
        self,
    ) -> Dict[str, Any]:
        """Build basic investigation metadata."""

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
            "status": investigation.status.value,
            "created_at": investigation.created_at,
            "updated_at": investigation.updated_at,
            "completed_at": investigation.completed_at,
            "participating_agents": list(
                investigation.participating_agents
            ),
            "metadata": dict(
                investigation.metadata
            ),
        }

    def _build_completion_assessment(
        self,
        task_summary: Dict[str, Any],
        hypothesis_summary: Dict[str, Any],
        shared_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Determine whether the investigation is report-ready."""

        status_counts = task_summary[
            "status_counts"
        ]

        pending_count = int(
            status_counts.get(
                TaskStatus.PENDING.value,
                0,
            )
        )

        running_count = int(
            status_counts.get(
                TaskStatus.RUNNING.value,
                0,
            )
        )

        blocked_count = int(
            status_counts.get(
                TaskStatus.BLOCKED.value,
                0,
            )
        )

        failed_count = int(
            status_counts.get(
                TaskStatus.FAILED.value,
                0,
            )
        )

        root_cause_present = bool(
            shared_results["root_cause"]
        )

        response_present = bool(
            shared_results["response"]
        )

        confirmed_hypothesis_count = len(
            hypothesis_summary.get(
                "confirmed_hypotheses",
                [],
            )
        )

        incomplete_task_count = (
            pending_count
            + running_count
            + blocked_count
        )

        if (
            self.context.investigation.status
            == InvestigationStatus.COMPLETED
            and incomplete_task_count == 0
            and root_cause_present
            and response_present
        ):
            readiness = "complete"

        elif (
            incomplete_task_count == 0
            and root_cause_present
        ):
            readiness = "report_ready"

        elif failed_count > 0:
            readiness = "partial_with_failures"

        elif blocked_count > 0:
            readiness = "awaiting_dependencies"

        else:
            readiness = "in_progress"

        return {
            "readiness": readiness,
            "incomplete_task_count": (
                incomplete_task_count
            ),
            "failed_task_count": failed_count,
            "root_cause_present": (
                root_cause_present
            ),
            "response_advisory_present": (
                response_present
            ),
            "confirmed_hypothesis_count": (
                confirmed_hypothesis_count
            ),
        }

    def build_report(
        self,
        include_event_log: bool = False,
        include_messages: bool = False,
        include_execution_results: bool = False,
    ) -> Dict[str, Any]:
        """Build the complete investigation report."""

        shared_results = (
            self._collect_shared_results()
        )

        task_summary = self._build_task_summary()
        agent_summary = self._build_agent_summary()
        findings_summary = (
            self._build_findings_summary()
        )
        evidence_summary = (
            self.evidence_manager.build_summary()
        )
        hypothesis_summary = (
            self._build_hypothesis_summary()
        )

        report = {
            "report_metadata": {
                "report_type": (
                    "multi_agent_investigation"
                ),
                "report_version": "0.7.0",
                "generated_at": utc_now(),
            },
            "investigation": (
                self._build_investigation_overview()
            ),
            "executive_summary": (
                self._build_executive_summary(
                    shared_results
                )
            ),
            "completion_assessment": (
                self._build_completion_assessment(
                    task_summary=task_summary,
                    hypothesis_summary=(
                        hypothesis_summary
                    ),
                    shared_results=shared_results,
                )
            ),
            "task_summary": task_summary,
            "agent_summary": agent_summary,
            "findings_summary": findings_summary,
            "evidence_summary": evidence_summary,
            "hypothesis_summary": (
                hypothesis_summary
            ),
            "triage_assessment": (
                shared_results["triage"]
            ),
            "indicators_of_compromise": (
                shared_results["iocs"]
            ),
            "mitre_attack_mapping": (
                shared_results["mitre"]
            ),
            "threat_intelligence": (
                shared_results[
                    "threat_intelligence"
                ]
            ),
            "historical_correlation": (
                shared_results["correlation"]
            ),
            "root_cause_assessment": (
                shared_results["root_cause"]
            ),
            "attack_chain": (
                shared_results["attack_chain"]
            ),
            "response_advisory": (
                shared_results["response"]
            ),
            "final_assessment": (
                self.context.investigation
                .final_assessment
            ),
        }

        if include_event_log:
            report["event_log"] = (
                self.context.get_event_log()
            )

        if include_messages:
            context_data = self.context.to_dict()

            report["agent_messages"] = (
                context_data.get(
                    "messages",
                    [],
                )
            )

        if include_execution_results:
            report["execution_results"] = [
                result.to_dict()
                for result
                in self.context.get_execution_results()
            ]

        self.context.set_shared_value(
            key="investigation_report",
            value=report,
            actor="investigation_reporter",
        )

        return report

    def build_compact_report(self) -> Dict[str, Any]:
        """Build a compact analyst summary."""

        full_report = self.build_report()

        return {
            "report_metadata": (
                full_report["report_metadata"]
            ),
            "investigation": (
                full_report["investigation"]
            ),
            "executive_summary": (
                full_report["executive_summary"]
            ),
            "completion_assessment": (
                full_report[
                    "completion_assessment"
                ]
            ),
            "top_findings": (
                full_report[
                    "findings_summary"
                ]["findings"][:5]
            ),
            "leading_hypothesis": (
                full_report[
                    "hypothesis_summary"
                ].get(
                    "leading_hypothesis"
                )
            ),
            "root_cause_assessment": (
                full_report[
                    "root_cause_assessment"
                ]
            ),
            "attack_chain": (
                full_report["attack_chain"]
            ),
            "response_advisory": (
                full_report[
                    "response_advisory"
                ]
            ),
            "evidence_integrity_score": (
                full_report[
                    "evidence_summary"
                ]["integrity_score"]
            ),
        }