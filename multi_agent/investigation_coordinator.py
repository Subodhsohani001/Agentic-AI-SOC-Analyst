from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from .agent_base import BaseInvestigationAgent
from .investigation_models import (
    AgentExecutionResult,
    Investigation,
    InvestigationStatus,
    InvestigationTask,
    TaskPriority,
    TaskStatus,
    utc_now,
)
from .shared_context import SharedInvestigationContext
from .task_router import (
    TaskRouteDecision,
    TaskRouter,
)


class InvestigationCoordinatorError(Exception):
    """Raised when the coordinator cannot continue an investigation."""


class InvestigationCoordinator:
    """
    Controls the complete lifecycle of a multi-agent investigation.

    Responsibilities:
    - Register specialist agents
    - Create and route investigation tasks
    - Start, pause, resume, complete, or fail investigations
    - Execute dependency-aware task chains
    - Track failed and blocked tasks
    - Prevent endless execution loops
    - Build a final investigation assessment
    """

    def __init__(
        self,
        investigation: Investigation,
        configuration: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not isinstance(investigation, Investigation):
            raise TypeError(
                "investigation must be an Investigation instance."
            )

        self.context = SharedInvestigationContext(
            investigation=investigation
        )
        self.router = TaskRouter(
            context=self.context
        )
        self.configuration = configuration or {}

        self._execution_round = 0
        self._started_at: Optional[str] = None
        self._last_execution_at: Optional[str] = None
        self._completed_at: Optional[str] = None
        self._failure_reason: Optional[str] = None

    @property
    def investigation(self) -> Investigation:
        """Return the active investigation."""

        return self.context.investigation

    def register_agent(
        self,
        agent: BaseInvestigationAgent,
        replace: bool = False,
    ) -> bool:
        """Register one specialist agent with the task router."""

        return self.router.register_agent(
            agent=agent,
            replace=replace,
        )

    def register_agents(
        self,
        agents: List[BaseInvestigationAgent],
        replace: bool = False,
    ) -> List[str]:
        """Register multiple specialist agents."""

        registered_agents: List[str] = []

        for agent in agents:
            self.register_agent(
                agent=agent,
                replace=replace,
            )
            registered_agents.append(agent.agent_name)

        return registered_agents

    def create_task(
        self,
        task_type: str,
        description: str,
        priority: TaskPriority = TaskPriority.P3,
        input_data: Optional[Dict[str, Any]] = None,
        dependencies: Optional[List[str]] = None,
        assigned_agent: str = "unassigned",
        route_immediately: bool = True,
        raise_errors: bool = False,
    ) -> tuple[InvestigationTask, Optional[TaskRouteDecision]]:
        """
        Create a new investigation task.

        When route_immediately=True, the task is automatically assigned
        to a capable registered specialist agent.
        """

        task = InvestigationTask(
            task_type=task_type.strip().lower(),
            assigned_agent=assigned_agent,
            description=description,
            priority=priority,
            input_data=input_data or {},
            dependencies=dependencies or [],
        )

        self.context.add_task(
            task=task,
            actor="investigation_coordinator",
        )

        route_decision: Optional[TaskRouteDecision] = None

        if route_immediately:
            route_decision = self.router.route_task(
                task=task,
                force_reassign=(
                    assigned_agent.strip().lower()
                    in {
                        "",
                        "unassigned",
                        "auto",
                        "task_router",
                    }
                ),
                raise_errors=raise_errors,
            )

        return task, route_decision

    def create_task_chain(
        self,
        task_definitions: List[Dict[str, Any]],
        route_immediately: bool = True,
        raise_errors: bool = False,
    ) -> List[InvestigationTask]:
        """
        Create a sequential task chain.

        Each task depends on the task created immediately before it,
        unless explicit dependencies are provided.

        Example task definition:

        {
            "task_type": "triage",
            "description": "Perform initial triage.",
            "priority": TaskPriority.P1,
            "input_data": {}
        }
        """

        created_tasks: List[InvestigationTask] = []
        previous_task_id: Optional[str] = None

        for definition in task_definitions:
            explicit_dependencies = definition.get(
                "dependencies"
            )

            if explicit_dependencies is None:
                dependencies = (
                    [previous_task_id]
                    if previous_task_id is not None
                    else []
                )
            else:
                dependencies = list(
                    explicit_dependencies
                )

            task, _ = self.create_task(
                task_type=definition["task_type"],
                description=definition["description"],
                priority=definition.get(
                    "priority",
                    TaskPriority.P3,
                ),
                input_data=definition.get(
                    "input_data",
                    {},
                ),
                dependencies=dependencies,
                assigned_agent=definition.get(
                    "assigned_agent",
                    "unassigned",
                ),
                route_immediately=route_immediately,
                raise_errors=raise_errors,
            )

            created_tasks.append(task)
            previous_task_id = task.task_id

        return created_tasks

    def start_investigation(self) -> None:
        """Start or resume the investigation."""

        allowed_statuses = {
            InvestigationStatus.CREATED,
            InvestigationStatus.AWAITING_EVIDENCE,
            InvestigationStatus.TRIAGING,
            InvestigationStatus.INVESTIGATING,
            InvestigationStatus.ANALYZING,
        }

        if self.investigation.status not in allowed_statuses:
            raise InvestigationCoordinatorError(
                "Investigation cannot start from status "
                f"{self.investigation.status.value}."
            )

        if self._started_at is None:
            self._started_at = utc_now()

        if self.investigation.status == InvestigationStatus.CREATED:
            self.context.set_investigation_status(
                status=InvestigationStatus.TRIAGING,
                actor="investigation_coordinator",
            )
        else:
            self.context.set_investigation_status(
                status=InvestigationStatus.INVESTIGATING,
                actor="investigation_coordinator",
            )

    def pause_for_evidence(
        self,
        reason: str,
    ) -> None:
        """Pause the investigation while waiting for more evidence."""

        self.context.set_shared_value(
            key="awaiting_evidence_reason",
            value=reason,
            actor="investigation_coordinator",
        )

        self.context.set_investigation_status(
            status=InvestigationStatus.AWAITING_EVIDENCE,
            actor="investigation_coordinator",
        )

    def fail_investigation(
        self,
        reason: str,
    ) -> None:
        """Mark the investigation as failed."""

        self._failure_reason = reason
        self._completed_at = utc_now()

        self.context.set_shared_value(
            key="investigation_failure_reason",
            value=reason,
            actor="investigation_coordinator",
        )

        self.context.set_investigation_status(
            status=InvestigationStatus.FAILED,
            actor="investigation_coordinator",
        )

    def complete_investigation(
        self,
        final_assessment: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Complete the investigation and store its final assessment."""

        assessment = (
            final_assessment
            or self.build_final_assessment()
        )

        self.investigation.final_assessment = assessment
        self._completed_at = utc_now()

        self.context.set_shared_value(
            key="final_investigation_assessment",
            value=assessment,
            actor="investigation_coordinator",
        )

        self.context.set_investigation_status(
            status=InvestigationStatus.COMPLETED,
            actor="investigation_coordinator",
        )

        return assessment

    def get_failed_tasks(self) -> List[InvestigationTask]:
        """Return every failed investigation task."""

        return self.context.get_tasks(
            status=TaskStatus.FAILED
        )

    def get_blocked_tasks(self) -> List[InvestigationTask]:
        """Return every blocked investigation task."""

        return self.context.get_tasks(
            status=TaskStatus.BLOCKED
        )

    def get_incomplete_tasks(self) -> List[InvestigationTask]:
        """Return tasks that have not reached a terminal state."""

        terminal_statuses = {
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.SKIPPED,
        }

        return [
            task
            for task in self.investigation.tasks
            if task.status not in terminal_statuses
        ]

    def get_ready_tasks(self) -> List[InvestigationTask]:
        """Return dependency-ready pending tasks."""

        return self.context.get_ready_tasks()

    def _resolve_blocked_tasks(self) -> int:
        """
        Re-evaluate blocked tasks.

        A blocked task returns to pending when every dependency is complete.
        """

        resolved_count = 0

        for task in self.get_blocked_tasks():
            if self.context.are_dependencies_completed(task):
                task.status = TaskStatus.PENDING
                task.error = None
                resolved_count += 1

        return resolved_count

    def _mark_tasks_blocked_by_failed_dependencies(self) -> int:
        """
        Block pending tasks whose dependencies have failed.

        This prevents dependent tasks from remaining pending forever.
        """

        task_map = {
            task.task_id: task
            for task in self.investigation.tasks
        }

        blocked_count = 0

        for task in self.context.get_tasks(
            status=TaskStatus.PENDING
        ):
            failed_dependencies = []

            for dependency_id in task.dependencies:
                dependency = task_map.get(
                    dependency_id
                )

                if (
                    dependency is not None
                    and dependency.status
                    == TaskStatus.FAILED
                ):
                    failed_dependencies.append(
                        dependency_id
                    )

            if failed_dependencies:
                task.mark_blocked(
                    "Blocked because dependent tasks failed: "
                    + ", ".join(failed_dependencies)
                )
                blocked_count += 1

        return blocked_count

    def _has_unroutable_pending_tasks(self) -> bool:
        """Check whether pending tasks lack capable registered agents."""

        for task in self.context.get_tasks(
            status=TaskStatus.PENDING
        ):
            assigned_agent = self.router.get_agent(
                task.assigned_agent
            )

            assignment_valid = (
                assigned_agent is not None
                and assigned_agent.supports_task(
                    task.task_type
                )
            )

            if (
                not assignment_valid
                and not self.router.can_route_task_type(
                    task.task_type
                )
            ):
                return True

        return False

    def route_pending_tasks(
        self,
        force_reassign: bool = False,
        raise_errors: bool = False,
    ) -> List[TaskRouteDecision]:
        """Route all currently pending tasks."""

        return self.router.route_all_pending_tasks(
            force_reassign=force_reassign,
            raise_errors=raise_errors,
        )

    def execute_round(
        self,
        raise_errors: bool = False,
    ) -> List[AgentExecutionResult]:
        """
        Execute one coordination round.

        A round processes the tasks that are ready at the start of
        the round. Newly unlocked tasks run in the following round.
        """

        if self.investigation.status in {
            InvestigationStatus.COMPLETED,
            InvestigationStatus.FAILED,
        }:
            return []

        self._execution_round += 1
        self._last_execution_at = utc_now()

        self._resolve_blocked_tasks()
        self._mark_tasks_blocked_by_failed_dependencies()

        ready_tasks = list(
            self.get_ready_tasks()
        )

        results: List[AgentExecutionResult] = []

        for task in ready_tasks:
            result = self.router.execute_task(
                task=task,
                auto_route=True,
                raise_errors=raise_errors,
            )

            if result is not None:
                results.append(result)

        return results

    def run_investigation(
        self,
        max_rounds: int = 100,
        fail_on_task_error: bool = False,
        auto_complete: bool = True,
        raise_errors: bool = False,
    ) -> Dict[str, Any]:
        """
        Run the investigation until no additional progress can be made.

        The max_rounds limit protects against routing or dependency loops.
        """

        if max_rounds <= 0:
            raise ValueError(
                "max_rounds must be greater than zero."
            )

        self.start_investigation()

        previous_terminal_count = -1
        stagnant_rounds = 0

        while self._execution_round < max_rounds:
            results = self.execute_round(
                raise_errors=raise_errors
            )

            failed_tasks = self.get_failed_tasks()

            if failed_tasks and fail_on_task_error:
                reason = (
                    "Investigation stopped because one or more "
                    "tasks failed."
                )
                self.fail_investigation(reason)
                break

            terminal_count = sum(
                1
                for task in self.investigation.tasks
                if task.status
                in {
                    TaskStatus.COMPLETED,
                    TaskStatus.FAILED,
                    TaskStatus.SKIPPED,
                }
            )

            if terminal_count == previous_terminal_count:
                stagnant_rounds += 1
            else:
                stagnant_rounds = 0

            previous_terminal_count = terminal_count

            incomplete_tasks = self.get_incomplete_tasks()

            if not incomplete_tasks:
                if auto_complete:
                    self.complete_investigation()
                break

            if not results:
                self._mark_tasks_blocked_by_failed_dependencies()

                ready_tasks = self.get_ready_tasks()

                if not ready_tasks:
                    if self._has_unroutable_pending_tasks():
                        self.pause_for_evidence(
                            "One or more pending tasks have no "
                            "registered capable agent."
                        )
                    elif self.get_blocked_tasks():
                        self.pause_for_evidence(
                            "Investigation contains blocked tasks "
                            "waiting for dependency resolution."
                        )
                    else:
                        self.pause_for_evidence(
                            "No executable investigation tasks remain."
                        )

                    break

            if stagnant_rounds >= 3:
                self.pause_for_evidence(
                    "Investigation made no measurable progress "
                    "for three execution rounds."
                )
                break

        if self._execution_round >= max_rounds:
            self.fail_investigation(
                "Maximum investigation execution rounds exceeded."
            )

        return self.get_status()

    def build_final_assessment(self) -> Dict[str, Any]:
        """
        Build a deterministic summary of investigation outcomes.

        A future investigation reporter and root-cause agent will enrich
        this assessment with narrative analysis.
        """

        completed_tasks = self.context.get_tasks(
            status=TaskStatus.COMPLETED
        )
        failed_tasks = self.get_failed_tasks()
        blocked_tasks = self.get_blocked_tasks()

        confirmed_hypotheses = [
            hypothesis
            for hypothesis in self.investigation.hypotheses
            if hypothesis.status.value == "confirmed"
        ]

        supported_hypotheses = [
            hypothesis
            for hypothesis in self.investigation.hypotheses
            if hypothesis.status.value == "supported"
        ]

        highest_confidence_hypothesis = None

        if self.investigation.hypotheses:
            highest_confidence_hypothesis = max(
                self.investigation.hypotheses,
                key=lambda hypothesis: hypothesis.confidence,
            )

        finding_severity_order = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "INFORMATIONAL": 0,
            "UNKNOWN": 0,
        }

        highest_severity_finding = None

        if self.investigation.findings:
            highest_severity_finding = max(
                self.investigation.findings,
                key=lambda finding: finding_severity_order.get(
                    finding.severity.upper(),
                    0,
                ),
            )

        assessment_status = "inconclusive"

        if confirmed_hypotheses:
            assessment_status = "confirmed"
        elif supported_hypotheses:
            assessment_status = "supported"
        elif completed_tasks and not failed_tasks:
            assessment_status = "completed_without_confirmation"
        elif failed_tasks:
            assessment_status = "partially_failed"

        return {
            "assessment_status": assessment_status,
            "investigation_id": (
                self.investigation.investigation_id
            ),
            "incident_id": self.investigation.incident_id,
            "severity": self.investigation.severity,
            "priority": self.investigation.priority.value,
            "completed_task_count": len(completed_tasks),
            "failed_task_count": len(failed_tasks),
            "blocked_task_count": len(blocked_tasks),
            "evidence_count": len(
                self.investigation.evidence
            ),
            "finding_count": len(
                self.investigation.findings
            ),
            "hypothesis_count": len(
                self.investigation.hypotheses
            ),
            "confirmed_hypothesis_count": len(
                confirmed_hypotheses
            ),
            "participating_agents": list(
                self.investigation.participating_agents
            ),
            "highest_confidence_hypothesis": (
                highest_confidence_hypothesis.to_dict()
                if highest_confidence_hypothesis
                else None
            ),
            "highest_severity_finding": (
                highest_severity_finding.to_dict()
                if highest_severity_finding
                else None
            ),
            "failed_tasks": [
                {
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "assigned_agent": task.assigned_agent,
                    "error": task.error,
                }
                for task in failed_tasks
            ],
            "blocked_tasks": [
                {
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "assigned_agent": task.assigned_agent,
                    "reason": task.error,
                }
                for task in blocked_tasks
            ],
            "generated_at": utc_now(),
        }

    def get_status(self) -> Dict[str, Any]:
        """Return coordinator and investigation runtime status."""

        return {
            "investigation": self.context.get_summary(),
            "coordinator": {
                "execution_round": self._execution_round,
                "started_at": self._started_at,
                "last_execution_at": self._last_execution_at,
                "completed_at": self._completed_at,
                "failure_reason": self._failure_reason,
                "registered_agents": (
                    self.router.get_agent_names()
                ),
                "ready_task_count": len(
                    self.get_ready_tasks()
                ),
                "incomplete_task_count": len(
                    self.get_incomplete_tasks()
                ),
                "failed_task_count": len(
                    self.get_failed_tasks()
                ),
                "blocked_task_count": len(
                    self.get_blocked_tasks()
                ),
            },
            "router": self.router.get_router_status(),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the coordinator and full shared context."""

        return {
            "status": self.get_status(),
            "shared_context": self.context.to_dict(),
        }