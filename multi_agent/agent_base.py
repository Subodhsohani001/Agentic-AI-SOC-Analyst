from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set

from .investigation_models import (
    AgentExecutionResult,
    AgentFinding,
    Evidence,
    InvestigationHypothesis,
    InvestigationTask,
    TaskStatus,
    utc_now,
)
from .shared_context import (
    AgentMessage,
    SharedInvestigationContext,
)


class AgentExecutionError(Exception):
    """Raised when an agent cannot complete its assigned task."""


class AgentValidationError(Exception):
    """Raised when an agent receives invalid input or context."""


class BaseInvestigationAgent(ABC):
    """
    Abstract base class for every multi-agent investigation specialist.

    Each specialist agent must implement:
    - supported_task_types
    - execute_task()

    The base class handles:
    - Agent registration
    - Task validation
    - Task lifecycle
    - Error isolation
    - Result normalization
    - Shared-context updates
    - Inter-agent messages
    """

    agent_name: str = "base_agent"
    description: str = "Base investigation agent"
    version: str = "0.7.0"

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
        self._execution_count = 0
        self._last_execution_at: Optional[str] = None

        self._validate_identity()
        self.context.register_agent(self.agent_name)

    def _validate_identity(self) -> None:
        """Validate the agent's required class-level identity."""

        if not self.agent_name.strip():
            raise AgentValidationError(
                "Agent must define a non-empty agent_name."
            )

        if self.agent_name == "base_agent":
            raise AgentValidationError(
                "Specialist agent must override agent_name."
            )

        if not self.description.strip():
            raise AgentValidationError(
                "Agent must define a non-empty description."
            )

    @property
    @abstractmethod
    def supported_task_types(self) -> Set[str]:
        """
        Return task types supported by this agent.

        Example:
            {"triage", "severity_assessment"}
        """

        raise NotImplementedError

    def supports_task(self, task_type: str) -> bool:
        """Check whether this agent supports a task type."""

        normalized_type = task_type.strip().lower()

        return normalized_type in {
            supported.strip().lower()
            for supported in self.supported_task_types
        }

    def validate_task(
        self,
        task: InvestigationTask,
    ) -> None:
        """Validate whether a task can be executed by this agent."""

        if not isinstance(task, InvestigationTask):
            raise AgentValidationError(
                "task must be an InvestigationTask instance."
            )

        if task.assigned_agent != self.agent_name:
            raise AgentValidationError(
                f"Task {task.task_id} is assigned to "
                f"{task.assigned_agent}, not {self.agent_name}."
            )

        if not self.supports_task(task.task_type):
            raise AgentValidationError(
                f"Agent {self.agent_name} does not support task type "
                f"{task.task_type!r}."
            )

        if task.status != TaskStatus.PENDING:
            raise AgentValidationError(
                f"Task {task.task_id} cannot be executed from status "
                f"{task.status.value}."
            )

        if not self.context.are_dependencies_completed(task):
            raise AgentValidationError(
                f"Task {task.task_id} has incomplete dependencies."
            )

    def get_pending_tasks(self) -> List[InvestigationTask]:
        """Return ready tasks assigned to this agent."""

        return self.context.get_ready_tasks(
            assigned_agent=self.agent_name
        )

    def get_configuration(
        self,
        key: str,
        default: Any = None,
    ) -> Any:
        """Return an agent configuration value."""

        return self.configuration.get(key, default)

    def get_shared_value(
        self,
        key: str,
        default: Any = None,
    ) -> Any:
        """Read a value from shared investigation state."""

        return self.context.get_shared_value(key, default)

    def set_shared_value(
        self,
        key: str,
        value: Any,
    ) -> None:
        """Write a value into shared investigation state."""

        self.context.set_shared_value(
            key=key,
            value=value,
            actor=self.agent_name,
        )

    def send_message(
        self,
        recipient_agent: str,
        subject: str,
        content: str,
        message_type: str = "information",
        related_task_id: Optional[str] = None,
        related_evidence_ids: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentMessage:
        """Send a message to another agent or broadcast channel."""

        message = AgentMessage(
            sender_agent=self.agent_name,
            recipient_agent=recipient_agent,
            subject=subject,
            content=content,
            message_type=message_type,
            related_task_id=related_task_id,
            related_evidence_ids=related_evidence_ids or [],
            metadata=metadata or {},
        )

        self.context.send_message(message)

        return message

    def get_messages(
        self,
        unread_only: bool = False,
        mark_as_read: bool = False,
    ) -> List[AgentMessage]:
        """Return messages addressed to this agent."""

        return self.context.get_messages_for_agent(
            agent_name=self.agent_name,
            unread_only=unread_only,
            mark_as_read=mark_as_read,
        )

    def create_success_result(
        self,
        summary: str,
        findings: Optional[List[AgentFinding]] = None,
        evidence: Optional[List[Evidence]] = None,
        proposed_tasks: Optional[
            List[InvestigationTask]
        ] = None,
        proposed_hypotheses: Optional[
            List[InvestigationHypothesis]
        ] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentExecutionResult:
        """Build a standardized successful execution result."""

        return AgentExecutionResult(
            agent_name=self.agent_name,
            success=True,
            summary=summary,
            findings=findings or [],
            evidence=evidence or [],
            proposed_tasks=proposed_tasks or [],
            proposed_hypotheses=proposed_hypotheses or [],
            metadata=metadata or {},
        )

    def create_failure_result(
        self,
        summary: str,
        error: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentExecutionResult:
        """Build a standardized failed execution result."""

        return AgentExecutionResult(
            agent_name=self.agent_name,
            success=False,
            summary=summary,
            error=error,
            metadata=metadata or {},
        )

    @abstractmethod
    def execute_task(
        self,
        task: InvestigationTask,
    ) -> AgentExecutionResult:
        """
        Perform the specialist agent's actual investigation work.

        Implementations should return AgentExecutionResult and should not
        directly change the task's lifecycle status.
        """

        raise NotImplementedError

    def run_task(
        self,
        task: InvestigationTask,
        raise_errors: bool = False,
    ) -> AgentExecutionResult:
        """
        Validate and execute one task safely.

        This method:
        1. Validates the task
        2. Marks it as running
        3. Calls execute_task()
        4. Records evidence, findings, hypotheses, and proposed tasks
        5. Completes or fails the task
        6. Isolates agent failures
        """

        try:
            self.validate_task(task)

            self.context.start_task(
                task_id=task.task_id,
                actor=self.agent_name,
            )

            result = self.execute_task(task)

            if not isinstance(result, AgentExecutionResult):
                raise AgentExecutionError(
                    f"{self.agent_name}.execute_task() must return "
                    "AgentExecutionResult."
                )

            if result.agent_name != self.agent_name:
                raise AgentExecutionError(
                    "Execution result agent_name does not match "
                    f"{self.agent_name}."
                )

            self.context.record_execution_result(result)

            if result.success:
                self.context.complete_task(
                    task_id=task.task_id,
                    result={
                        "summary": result.summary,
                        "execution_id": result.execution_id,
                        "finding_count": len(result.findings),
                        "evidence_count": len(result.evidence),
                        "proposed_task_count": len(
                            result.proposed_tasks
                        ),
                        "proposed_hypothesis_count": len(
                            result.proposed_hypotheses
                        ),
                        "metadata": result.metadata,
                    },
                    actor=self.agent_name,
                )
            else:
                self.context.fail_task(
                    task_id=task.task_id,
                    error=result.error or result.summary,
                    actor=self.agent_name,
                )

            self._execution_count += 1
            self._last_execution_at = utc_now()

            return result

        except Exception as exc:
            error_message = f"{type(exc).__name__}: {exc}"

            existing_task = self.context.get_task(task.task_id)

            if (
                existing_task is not None
                and existing_task.status
                not in {
                    TaskStatus.COMPLETED,
                    TaskStatus.FAILED,
                    TaskStatus.SKIPPED,
                }
            ):
                try:
                    self.context.fail_task(
                        task_id=task.task_id,
                        error=error_message,
                        actor=self.agent_name,
                    )
                except Exception:
                    pass

            failure_result = self.create_failure_result(
                summary=(
                    f"{self.agent_name} failed to execute "
                    f"task {task.task_id}."
                ),
                error=error_message,
                metadata={
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                },
            )

            self.context.record_execution_result(
                failure_result
            )

            self._execution_count += 1
            self._last_execution_at = utc_now()

            if raise_errors:
                raise

            return failure_result

    def run_next_task(
        self,
        raise_errors: bool = False,
    ) -> Optional[AgentExecutionResult]:
        """
        Execute the highest-priority ready task assigned to this agent.

        Returns None when no ready task exists.
        """

        pending_tasks = self.get_pending_tasks()

        if not pending_tasks:
            return None

        return self.run_task(
            task=pending_tasks[0],
            raise_errors=raise_errors,
        )

    def run_all_ready_tasks(
        self,
        raise_errors: bool = False,
    ) -> List[AgentExecutionResult]:
        """
        Execute every currently ready task assigned to this agent.

        The ready-task list is recalculated after each execution so that
        newly unblocked dependent tasks can also run.
        """

        results: List[AgentExecutionResult] = []
        processed_task_ids: Set[str] = set()

        while True:
            ready_tasks = [
                task
                for task in self.get_pending_tasks()
                if task.task_id not in processed_task_ids
            ]

            if not ready_tasks:
                break

            task = ready_tasks[0]
            processed_task_ids.add(task.task_id)

            result = self.run_task(
                task=task,
                raise_errors=raise_errors,
            )

            results.append(result)

        return results

    def get_agent_status(self) -> Dict[str, Any]:
        """Return runtime information about this agent."""

        pending_tasks = self.get_pending_tasks()

        return {
            "agent_name": self.agent_name,
            "description": self.description,
            "version": self.version,
            "supported_task_types": sorted(
                self.supported_task_types
            ),
            "registered": self.context.is_agent_registered(
                self.agent_name
            ),
            "execution_count": self._execution_count,
            "last_execution_at": self._last_execution_at,
            "ready_task_count": len(pending_tasks),
            "ready_task_ids": [
                task.task_id for task in pending_tasks
            ],
            "configuration_keys": sorted(
                self.configuration.keys()
            ),
        }

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"agent_name={self.agent_name!r}, "
            f"version={self.version!r})"
        )