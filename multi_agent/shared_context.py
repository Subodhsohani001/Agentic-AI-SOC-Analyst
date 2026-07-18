from __future__ import annotations

from dataclasses import asdict, dataclass, field
from threading import RLock
from typing import Any, Dict, List, Optional

from .investigation_models import (
    AgentExecutionResult,
    AgentFinding,
    Evidence,
    Investigation,
    InvestigationHypothesis,
    InvestigationStatus,
    InvestigationTask,
    TaskStatus,
    generate_identifier,
    utc_now,
)


@dataclass
class AgentMessage:
    """
    A message exchanged between agents during an investigation.

    recipient_agent can be:
    - A specific agent name, such as "ioc_agent"
    - "broadcast" for every participating agent
    - "coordinator" for the investigation coordinator
    """

    sender_agent: str
    recipient_agent: str
    subject: str
    content: str
    message_type: str = "information"
    related_task_id: Optional[str] = None
    related_evidence_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    message_id: str = field(
        default_factory=lambda: generate_identifier("MSG")
    )
    created_at: str = field(default_factory=utc_now)
    read_by: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.sender_agent.strip():
            raise ValueError("sender_agent cannot be empty.")

        if not self.recipient_agent.strip():
            raise ValueError("recipient_agent cannot be empty.")

        if not self.subject.strip():
            raise ValueError("subject cannot be empty.")

        if not self.content.strip():
            raise ValueError("content cannot be empty.")

    def mark_read(self, agent_name: str) -> None:
        """Mark this message as read by an agent."""

        if agent_name and agent_name not in self.read_by:
            self.read_by.append(agent_name)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SharedInvestigationContext:
    """
    Thread-safe shared state for a multi-agent investigation.

    Every specialist agent reads from and writes to this context instead of
    maintaining isolated copies of the investigation.
    """

    def __init__(self, investigation: Investigation) -> None:
        if not isinstance(investigation, Investigation):
            raise TypeError(
                "investigation must be an Investigation instance."
            )

        self._investigation = investigation
        self._messages: List[AgentMessage] = []
        self._execution_results: List[AgentExecutionResult] = []
        self._shared_data: Dict[str, Any] = {}
        self._event_log: List[Dict[str, Any]] = []
        self._lock = RLock()

        self._record_event(
            event_type="context_created",
            actor="system",
            details={
                "investigation_id": investigation.investigation_id,
                "incident_id": investigation.incident_id,
            },
        )

    @property
    def investigation(self) -> Investigation:
        """
        Return the active investigation.

        Agents should preferably use the context methods to modify it.
        """

        return self._investigation

    def _record_event(
        self,
        event_type: str,
        actor: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Write an internal event to the context event log."""

        event = {
            "event_id": generate_identifier("EVT"),
            "event_type": event_type,
            "actor": actor,
            "details": details or {},
            "created_at": utc_now(),
        }

        self._event_log.append(event)

    def register_agent(self, agent_name: str) -> bool:
        """
        Register an agent as a participant in the investigation.

        Returns True when newly registered and False if already registered.
        """

        normalized_name = agent_name.strip()

        if not normalized_name:
            raise ValueError("agent_name cannot be empty.")

        with self._lock:
            if normalized_name in self._investigation.participating_agents:
                return False

            self._investigation.participating_agents.append(normalized_name)
            self._investigation.updated_at = utc_now()

            self._record_event(
                event_type="agent_registered",
                actor=normalized_name,
                details={"agent_name": normalized_name},
            )

            return True

    def is_agent_registered(self, agent_name: str) -> bool:
        """Check whether an agent is registered."""

        with self._lock:
            return agent_name in self._investigation.participating_agents

    def set_investigation_status(
        self,
        status: InvestigationStatus,
        actor: str = "coordinator",
    ) -> None:
        """Change the lifecycle status of the investigation."""

        if not isinstance(status, InvestigationStatus):
            raise TypeError(
                "status must be an InvestigationStatus value."
            )

        with self._lock:
            previous_status = self._investigation.status
            self._investigation.set_status(status)

            self._record_event(
                event_type="investigation_status_changed",
                actor=actor,
                details={
                    "previous_status": previous_status.value,
                    "new_status": status.value,
                },
            )

    def add_task(
        self,
        task: InvestigationTask,
        actor: str = "coordinator",
    ) -> bool:
        """
        Add a task to the investigation.

        Returns False when the task ID already exists.
        """

        if not isinstance(task, InvestigationTask):
            raise TypeError(
                "task must be an InvestigationTask instance."
            )

        with self._lock:
            if self.get_task(task.task_id) is not None:
                return False

            self._investigation.add_task(task)

            self._record_event(
                event_type="task_added",
                actor=actor,
                details={
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "assigned_agent": task.assigned_agent,
                    "priority": task.priority.value,
                },
            )

            return True

    def get_task(self, task_id: str) -> Optional[InvestigationTask]:
        """Return a task by ID."""

        with self._lock:
            for task in self._investigation.tasks:
                if task.task_id == task_id:
                    return task

        return None

    def get_tasks(
        self,
        assigned_agent: Optional[str] = None,
        status: Optional[TaskStatus] = None,
    ) -> List[InvestigationTask]:
        """Return tasks filtered by agent and/or status."""

        with self._lock:
            tasks = list(self._investigation.tasks)

        if assigned_agent is not None:
            tasks = [
                task
                for task in tasks
                if task.assigned_agent == assigned_agent
            ]

        if status is not None:
            tasks = [
                task
                for task in tasks
                if task.status == status
            ]

        return tasks

    def are_dependencies_completed(
        self,
        task: InvestigationTask,
    ) -> bool:
        """Check whether all dependencies of a task are completed."""

        if not task.dependencies:
            return True

        with self._lock:
            task_map = {
                existing.task_id: existing
                for existing in self._investigation.tasks
            }

            for dependency_id in task.dependencies:
                dependency = task_map.get(dependency_id)

                if dependency is None:
                    return False

                if dependency.status != TaskStatus.COMPLETED:
                    return False

        return True

    def get_ready_tasks(
        self,
        assigned_agent: Optional[str] = None,
    ) -> List[InvestigationTask]:
        """
        Return pending tasks whose dependencies have been completed.

        Tasks are sorted from highest to lowest priority.
        """

        priority_order = {
            "P1": 1,
            "P2": 2,
            "P3": 3,
            "P4": 4,
        }

        with self._lock:
            ready_tasks = [
                task
                for task in self._investigation.tasks
                if task.status == TaskStatus.PENDING
                and (
                    assigned_agent is None
                    or task.assigned_agent == assigned_agent
                )
                and self.are_dependencies_completed(task)
            ]

        return sorted(
            ready_tasks,
            key=lambda task: (
                priority_order.get(task.priority.value, 99),
                task.created_at,
            ),
        )

    def start_task(
        self,
        task_id: str,
        actor: str,
    ) -> InvestigationTask:
        """Mark a task as running."""

        with self._lock:
            task = self.get_task(task_id)

            if task is None:
                raise KeyError(f"Task not found: {task_id}")

            if task.status != TaskStatus.PENDING:
                raise ValueError(
                    f"Task {task_id} cannot start from status "
                    f"{task.status.value}."
                )

            if not self.are_dependencies_completed(task):
                task.mark_blocked(
                    "One or more task dependencies are incomplete."
                )

                self._record_event(
                    event_type="task_blocked",
                    actor=actor,
                    details={
                        "task_id": task_id,
                        "reason": task.error,
                    },
                )

                raise RuntimeError(
                    f"Task {task_id} has incomplete dependencies."
                )

            task.mark_running()
            self._investigation.updated_at = utc_now()

            self._record_event(
                event_type="task_started",
                actor=actor,
                details={"task_id": task_id},
            )

            return task

    def complete_task(
        self,
        task_id: str,
        result: Dict[str, Any],
        actor: str,
    ) -> InvestigationTask:
        """Mark a running task as completed."""

        with self._lock:
            task = self.get_task(task_id)

            if task is None:
                raise KeyError(f"Task not found: {task_id}")

            if task.status != TaskStatus.RUNNING:
                raise ValueError(
                    f"Task {task_id} cannot complete from status "
                    f"{task.status.value}."
                )

            task.mark_completed(result)
            self._investigation.updated_at = utc_now()

            self._record_event(
                event_type="task_completed",
                actor=actor,
                details={
                    "task_id": task_id,
                    "result_summary": result.get("summary"),
                },
            )

            return task

    def fail_task(
        self,
        task_id: str,
        error: str,
        actor: str,
    ) -> InvestigationTask:
        """Mark a task as failed."""

        with self._lock:
            task = self.get_task(task_id)

            if task is None:
                raise KeyError(f"Task not found: {task_id}")

            if task.status not in {
                TaskStatus.PENDING,
                TaskStatus.ASSIGNED,
                TaskStatus.RUNNING,
                TaskStatus.BLOCKED,
            }:
                raise ValueError(
                    f"Task {task_id} cannot fail from status "
                    f"{task.status.value}."
                )

            task.mark_failed(error)
            self._investigation.updated_at = utc_now()

            self._record_event(
                event_type="task_failed",
                actor=actor,
                details={
                    "task_id": task_id,
                    "error": error,
                },
            )

            return task

    def add_evidence(
        self,
        evidence: Evidence,
        actor: str,
    ) -> bool:
        """Add evidence while preventing duplicate evidence IDs."""

        if not isinstance(evidence, Evidence):
            raise TypeError("evidence must be an Evidence instance.")

        with self._lock:
            if self.get_evidence(evidence.evidence_id) is not None:
                return False

            self._investigation.add_evidence(evidence)

            self._record_event(
                event_type="evidence_added",
                actor=actor,
                details={
                    "evidence_id": evidence.evidence_id,
                    "evidence_type": evidence.evidence_type.value,
                    "source": evidence.source,
                },
            )

            return True

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        """Return evidence by ID."""

        with self._lock:
            for evidence in self._investigation.evidence:
                if evidence.evidence_id == evidence_id:
                    return evidence

        return None

    def get_evidence_by_type(
        self,
        evidence_type: str,
    ) -> List[Evidence]:
        """
        Return evidence matching an EvidenceType value.

        Example:
            context.get_evidence_by_type("ioc")
        """

        normalized_type = evidence_type.strip().lower()

        with self._lock:
            return [
                evidence
                for evidence in self._investigation.evidence
                if evidence.evidence_type.value == normalized_type
            ]

    def add_finding(
        self,
        finding: AgentFinding,
        actor: Optional[str] = None,
    ) -> bool:
        """Add an agent finding to the investigation."""

        if not isinstance(finding, AgentFinding):
            raise TypeError(
                "finding must be an AgentFinding instance."
            )

        with self._lock:
            if self.get_finding(finding.finding_id) is not None:
                return False

            self._investigation.add_finding(finding)

            self._record_event(
                event_type="finding_added",
                actor=actor or finding.agent_name,
                details={
                    "finding_id": finding.finding_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                },
            )

            return True

    def get_finding(
        self,
        finding_id: str,
    ) -> Optional[AgentFinding]:
        """Return a finding by ID."""

        with self._lock:
            for finding in self._investigation.findings:
                if finding.finding_id == finding_id:
                    return finding

        return None

    def get_findings_by_agent(
        self,
        agent_name: str,
    ) -> List[AgentFinding]:
        """Return every finding produced by a specific agent."""

        with self._lock:
            return [
                finding
                for finding in self._investigation.findings
                if finding.agent_name == agent_name
            ]

    def add_hypothesis(
        self,
        hypothesis: InvestigationHypothesis,
        actor: Optional[str] = None,
    ) -> bool:
        """Add an investigation hypothesis."""

        if not isinstance(
            hypothesis,
            InvestigationHypothesis,
        ):
            raise TypeError(
                "hypothesis must be an InvestigationHypothesis instance."
            )

        with self._lock:
            if self.get_hypothesis(
                hypothesis.hypothesis_id
            ) is not None:
                return False

            self._investigation.add_hypothesis(hypothesis)

            self._record_event(
                event_type="hypothesis_added",
                actor=actor or hypothesis.proposed_by,
                details={
                    "hypothesis_id": hypothesis.hypothesis_id,
                    "title": hypothesis.title,
                    "confidence": hypothesis.confidence,
                    "status": hypothesis.status.value,
                },
            )

            return True

    def get_hypothesis(
        self,
        hypothesis_id: str,
    ) -> Optional[InvestigationHypothesis]:
        """Return a hypothesis by ID."""

        with self._lock:
            for hypothesis in self._investigation.hypotheses:
                if hypothesis.hypothesis_id == hypothesis_id:
                    return hypothesis

        return None

    def send_message(self, message: AgentMessage) -> bool:
        """Add an inter-agent message."""

        if not isinstance(message, AgentMessage):
            raise TypeError(
                "message must be an AgentMessage instance."
            )

        with self._lock:
            if any(
                existing.message_id == message.message_id
                for existing in self._messages
            ):
                return False

            self._messages.append(message)

            self._record_event(
                event_type="message_sent",
                actor=message.sender_agent,
                details={
                    "message_id": message.message_id,
                    "recipient_agent": message.recipient_agent,
                    "subject": message.subject,
                    "message_type": message.message_type,
                },
            )

            return True

    def get_messages_for_agent(
        self,
        agent_name: str,
        unread_only: bool = False,
        mark_as_read: bool = False,
    ) -> List[AgentMessage]:
        """
        Return direct and broadcast messages available to an agent.
        """

        with self._lock:
            messages = [
                message
                for message in self._messages
                if message.recipient_agent in {
                    agent_name,
                    "broadcast",
                }
                and (
                    not unread_only
                    or agent_name not in message.read_by
                )
            ]

            if mark_as_read:
                for message in messages:
                    message.mark_read(agent_name)

        return messages

    def record_execution_result(
        self,
        result: AgentExecutionResult,
    ) -> bool:
        """
        Store an agent execution result and merge its outputs into
        the shared investigation.
        """

        if not isinstance(result, AgentExecutionResult):
            raise TypeError(
                "result must be an AgentExecutionResult instance."
            )

        with self._lock:
            if any(
                existing.execution_id == result.execution_id
                for existing in self._execution_results
            ):
                return False

            self._execution_results.append(result)
            self.register_agent(result.agent_name)

            for evidence in result.evidence:
                self.add_evidence(evidence, actor=result.agent_name)

            for finding in result.findings:
                self.add_finding(finding, actor=result.agent_name)

            for task in result.proposed_tasks:
                self.add_task(task, actor=result.agent_name)

            for hypothesis in result.proposed_hypotheses:
                self.add_hypothesis(
                    hypothesis,
                    actor=result.agent_name,
                )

            self._record_event(
                event_type="agent_execution_recorded",
                actor=result.agent_name,
                details={
                    "execution_id": result.execution_id,
                    "success": result.success,
                    "finding_count": len(result.findings),
                    "evidence_count": len(result.evidence),
                    "proposed_task_count": len(
                        result.proposed_tasks
                    ),
                    "proposed_hypothesis_count": len(
                        result.proposed_hypotheses
                    ),
                    "error": result.error,
                },
            )

            return True

    def get_execution_results(
        self,
        agent_name: Optional[str] = None,
    ) -> List[AgentExecutionResult]:
        """Return all execution results or results for one agent."""

        with self._lock:
            results = list(self._execution_results)

        if agent_name is not None:
            results = [
                result
                for result in results
                if result.agent_name == agent_name
            ]

        return results

    def set_shared_value(
        self,
        key: str,
        value: Any,
        actor: str,
    ) -> None:
        """
        Store arbitrary shared investigation data.

        Examples:
        - normalized_iocs
        - threat_intelligence_summary
        - attack_chain
        - host_profile
        """

        normalized_key = key.strip()

        if not normalized_key:
            raise ValueError("Shared data key cannot be empty.")

        with self._lock:
            self._shared_data[normalized_key] = value

            self._record_event(
                event_type="shared_value_set",
                actor=actor,
                details={"key": normalized_key},
            )

    def get_shared_value(
        self,
        key: str,
        default: Any = None,
    ) -> Any:
        """Return a shared value."""

        with self._lock:
            return self._shared_data.get(key, default)

    def delete_shared_value(
        self,
        key: str,
        actor: str,
    ) -> bool:
        """Delete a shared value if it exists."""

        with self._lock:
            if key not in self._shared_data:
                return False

            del self._shared_data[key]

            self._record_event(
                event_type="shared_value_deleted",
                actor=actor,
                details={"key": key},
            )

            return True

    def get_event_log(
        self,
        event_type: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return context events with optional filters."""

        with self._lock:
            events = list(self._event_log)

        if event_type is not None:
            events = [
                event
                for event in events
                if event["event_type"] == event_type
            ]

        if actor is not None:
            events = [
                event
                for event in events
                if event["actor"] == actor
            ]

        return events

    def get_summary(self) -> Dict[str, Any]:
        """Return a compact investigation progress summary."""

        with self._lock:
            tasks = self._investigation.tasks

            task_counts = {
                status.value: sum(
                    1 for task in tasks if task.status == status
                )
                for status in TaskStatus
            }

            return {
                "investigation_id": (
                    self._investigation.investigation_id
                ),
                "incident_id": self._investigation.incident_id,
                "status": self._investigation.status.value,
                "severity": self._investigation.severity,
                "priority": self._investigation.priority.value,
                "participating_agents": list(
                    self._investigation.participating_agents
                ),
                "task_counts": task_counts,
                "evidence_count": len(
                    self._investigation.evidence
                ),
                "finding_count": len(
                    self._investigation.findings
                ),
                "hypothesis_count": len(
                    self._investigation.hypotheses
                ),
                "message_count": len(self._messages),
                "execution_count": len(
                    self._execution_results
                ),
                "shared_data_keys": list(
                    self._shared_data.keys()
                ),
                "event_count": len(self._event_log),
            }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the entire shared context."""

        with self._lock:
            return {
                "investigation": self._investigation.to_dict(),
                "messages": [
                    message.to_dict()
                    for message in self._messages
                ],
                "execution_results": [
                    result.to_dict()
                    for result in self._execution_results
                ],
                "shared_data": dict(self._shared_data),
                "event_log": list(self._event_log),
                "summary": self.get_summary(),
            }