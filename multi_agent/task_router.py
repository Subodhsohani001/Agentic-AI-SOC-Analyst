from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set

from .agent_base import BaseInvestigationAgent
from .investigation_models import (
    InvestigationTask,
    TaskPriority,
    TaskStatus,
    generate_identifier,
    utc_now,
)
from .shared_context import SharedInvestigationContext


class TaskRoutingError(Exception):
    """Raised when a task cannot be routed to a suitable agent."""


class AgentRegistrationError(Exception):
    """Raised when an invalid or duplicate agent is registered."""


@dataclass
class TaskRouteDecision:
    """
    Records how and why a task was assigned to an agent.
    """

    task_id: str
    task_type: str
    selected_agent: Optional[str]
    success: bool
    reason: str
    candidate_agents: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    decision_id: str = field(
        default_factory=lambda: generate_identifier("RTE")
    )
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TaskRouter:
    """
    Routes investigation tasks to registered specialist agents.

    Responsibilities:
    - Register and remove agents
    - Maintain task-type capability mappings
    - Select capable agents
    - Prefer less-loaded agents
    - Preserve explicit valid assignments
    - Reassign invalid or unavailable assignments
    - Record every routing decision
    """

    def __init__(
        self,
        context: SharedInvestigationContext,
    ) -> None:
        if not isinstance(context, SharedInvestigationContext):
            raise TypeError(
                "context must be a SharedInvestigationContext instance."
            )

        self.context = context
        self._agents: Dict[str, BaseInvestigationAgent] = {}
        self._capability_map: Dict[str, Set[str]] = {}
        self._routing_history: List[TaskRouteDecision] = []

    @staticmethod
    def _normalize_task_type(task_type: str) -> str:
        """Normalize a task type for reliable matching."""

        normalized = task_type.strip().lower()

        if not normalized:
            raise ValueError("task_type cannot be empty.")

        return normalized

    def register_agent(
        self,
        agent: BaseInvestigationAgent,
        replace: bool = False,
    ) -> bool:
        """
        Register an agent and index its supported task types.

        Returns True when registered successfully.

        If replace is False, registering another agent with the same
        agent_name raises AgentRegistrationError.
        """

        if not isinstance(agent, BaseInvestigationAgent):
            raise TypeError(
                "agent must be a BaseInvestigationAgent instance."
            )

        agent_name = agent.agent_name.strip()

        if not agent_name:
            raise AgentRegistrationError(
                "Agent must have a non-empty agent_name."
            )

        if agent.context is not self.context:
            raise AgentRegistrationError(
                f"Agent {agent_name} belongs to a different "
                "SharedInvestigationContext."
            )

        if agent_name in self._agents and not replace:
            raise AgentRegistrationError(
                f"Agent already registered: {agent_name}"
            )

        if replace and agent_name in self._agents:
            self.unregister_agent(agent_name)

        normalized_capabilities = {
            self._normalize_task_type(task_type)
            for task_type in agent.supported_task_types
        }

        if not normalized_capabilities:
            raise AgentRegistrationError(
                f"Agent {agent_name} does not declare any "
                "supported task types."
            )

        self._agents[agent_name] = agent

        for task_type in normalized_capabilities:
            self._capability_map.setdefault(
                task_type,
                set(),
            ).add(agent_name)

        self.context.register_agent(agent_name)

        return True

    def unregister_agent(self, agent_name: str) -> bool:
        """
        Remove an agent from the router.

        The investigation participation history is preserved in the
        shared context.
        """

        normalized_name = agent_name.strip()

        if normalized_name not in self._agents:
            return False

        del self._agents[normalized_name]

        empty_capabilities: List[str] = []

        for task_type, agent_names in self._capability_map.items():
            agent_names.discard(normalized_name)

            if not agent_names:
                empty_capabilities.append(task_type)

        for task_type in empty_capabilities:
            del self._capability_map[task_type]

        return True

    def get_agent(
        self,
        agent_name: str,
    ) -> Optional[BaseInvestigationAgent]:
        """Return a registered agent by name."""

        return self._agents.get(agent_name)

    def get_registered_agents(
        self,
    ) -> List[BaseInvestigationAgent]:
        """Return all registered agents."""

        return list(self._agents.values())

    def get_agent_names(self) -> List[str]:
        """Return registered agent names."""

        return sorted(self._agents.keys())

    def get_agents_for_task_type(
        self,
        task_type: str,
    ) -> List[BaseInvestigationAgent]:
        """Return agents capable of handling a task type."""

        normalized_type = self._normalize_task_type(task_type)

        agent_names = sorted(
            self._capability_map.get(
                normalized_type,
                set(),
            )
        )

        return [
            self._agents[agent_name]
            for agent_name in agent_names
            if agent_name in self._agents
        ]

    def can_route_task_type(self, task_type: str) -> bool:
        """Check whether at least one agent supports a task type."""

        return bool(self.get_agents_for_task_type(task_type))

    def _calculate_agent_load(
        self,
        agent_name: str,
    ) -> Dict[str, int]:
        """
        Calculate the current task load for an agent.

        Lower active load is preferred during automatic routing.
        """

        tasks = self.context.get_tasks(
            assigned_agent=agent_name
        )

        pending_count = sum(
            1
            for task in tasks
            if task.status == TaskStatus.PENDING
        )

        running_count = sum(
            1
            for task in tasks
            if task.status == TaskStatus.RUNNING
        )

        blocked_count = sum(
            1
            for task in tasks
            if task.status == TaskStatus.BLOCKED
        )

        active_load = (
            pending_count
            + (running_count * 2)
            + blocked_count
        )

        return {
            "pending": pending_count,
            "running": running_count,
            "blocked": blocked_count,
            "active_load": active_load,
        }

    def _select_best_agent(
        self,
        candidates: List[BaseInvestigationAgent],
    ) -> BaseInvestigationAgent:
        """
        Select the least-loaded capable agent.

        Ties are resolved alphabetically to keep routing deterministic.
        """

        if not candidates:
            raise TaskRoutingError(
                "No candidate agents were provided."
            )

        return min(
            candidates,
            key=lambda agent: (
                self._calculate_agent_load(
                    agent.agent_name
                )["active_load"],
                agent.agent_name,
            ),
        )

    def _record_decision(
        self,
        decision: TaskRouteDecision,
    ) -> TaskRouteDecision:
        """Store a routing decision."""

        self._routing_history.append(decision)

        self.context.set_shared_value(
            key="latest_task_route_decision",
            value=decision.to_dict(),
            actor="task_router",
        )

        return decision

    def route_task(
        self,
        task: InvestigationTask,
        force_reassign: bool = False,
        raise_errors: bool = False,
    ) -> TaskRouteDecision:
        """
        Route one task to a suitable registered agent.

        Routing logic:
        1. Preserve an explicit valid assignment unless force_reassign=True
        2. Find every capable registered agent
        3. Select the least-loaded candidate
        4. Update task.assigned_agent
        5. Record the routing decision
        """

        if not isinstance(task, InvestigationTask):
            raise TypeError(
                "task must be an InvestigationTask instance."
            )

        normalized_type = self._normalize_task_type(
            task.task_type
        )

        if task.status not in {
            TaskStatus.PENDING,
            TaskStatus.ASSIGNED,
            TaskStatus.BLOCKED,
        }:
            message = (
                f"Task {task.task_id} cannot be routed from "
                f"status {task.status.value}."
            )

            decision = TaskRouteDecision(
                task_id=task.task_id,
                task_type=normalized_type,
                selected_agent=None,
                success=False,
                reason=message,
            )

            self._record_decision(decision)

            if raise_errors:
                raise TaskRoutingError(message)

            return decision

        current_agent = self._agents.get(
            task.assigned_agent
        )

        current_assignment_valid = (
            current_agent is not None
            and current_agent.supports_task(
                normalized_type
            )
        )

        if (
            current_agent is not None
            and current_agent.supports_task(normalized_type)
            and not force_reassign
        ):
            decision = TaskRouteDecision(
                task_id=task.task_id,
                task_type=normalized_type,
                selected_agent=current_agent.agent_name,
                success=True,
                reason=(
                    "Existing assignment is valid and was preserved."
                ),
                
                metadata={
                    "assignment_preserved": True,
                    "agent_load": self._calculate_agent_load(
                        current_agent.agent_name
                    ),
                },
            )

            return self._record_decision(decision)

        candidates = self.get_agents_for_task_type(
            normalized_type
        )

        if not candidates:
            message = (
                f"No registered agent supports task type "
                f"{normalized_type!r}."
            )

            decision = TaskRouteDecision(
                task_id=task.task_id,
                task_type=normalized_type,
                selected_agent=None,
                success=False,
                reason=message,
                candidate_agents=[],
                metadata={
                    "previous_assignment": task.assigned_agent,
                },
            )

            self._record_decision(decision)

            if raise_errors:
                raise TaskRoutingError(message)

            return decision

        selected_agent = self._select_best_agent(
            candidates
        )

        previous_assignment = task.assigned_agent
        task.assigned_agent = selected_agent.agent_name

        if task.status == TaskStatus.BLOCKED:
            task.status = TaskStatus.PENDING
            task.error = None

        task.status = TaskStatus.PENDING

        decision = TaskRouteDecision(
            task_id=task.task_id,
            task_type=normalized_type,
            selected_agent=selected_agent.agent_name,
            success=True,
            reason=(
                "Task assigned to the least-loaded capable agent."
            ),
            candidate_agents=[
                candidate.agent_name
                for candidate in candidates
            ],
            metadata={
                "previous_assignment": previous_assignment,
                "force_reassign": force_reassign,
                "selected_agent_load": (
                    self._calculate_agent_load(
                        selected_agent.agent_name
                    )
                ),
            },
        )

        return self._record_decision(decision)

    def route_unassigned_tasks(
        self,
        placeholder_names: Optional[Set[str]] = None,
        raise_errors: bool = False,
    ) -> List[TaskRouteDecision]:
        """
        Route every pending task that has no meaningful assignment.

        Default placeholder assignments:
        - ""
        - "unassigned"
        - "auto"
        - "task_router"
        """

        placeholders = {
            "",
            "unassigned",
            "auto",
            "task_router",
        }

        if placeholder_names:
            placeholders.update(
                name.strip().lower()
                for name in placeholder_names
            )

        decisions: List[TaskRouteDecision] = []

        for task in self.context.get_tasks(
            status=TaskStatus.PENDING
        ):
            current_assignment = (
                task.assigned_agent.strip().lower()
            )

            assignment_invalid = (
                current_assignment in placeholders
                or current_assignment not in self._agents
            )

            if assignment_invalid:
                decisions.append(
                    self.route_task(
                        task=task,
                        force_reassign=True,
                        raise_errors=raise_errors,
                    )
                )

        return decisions

    def route_all_pending_tasks(
        self,
        force_reassign: bool = False,
        raise_errors: bool = False,
    ) -> List[TaskRouteDecision]:
        """Route every pending task in the investigation."""

        decisions: List[TaskRouteDecision] = []

        for task in self.context.get_tasks(
            status=TaskStatus.PENDING
        ):
            decisions.append(
                self.route_task(
                    task=task,
                    force_reassign=force_reassign,
                    raise_errors=raise_errors,
                )
            )

        return decisions

    def create_and_route_task(
        self,
        task_type: str,
        description: str,
        priority: TaskPriority = TaskPriority.P3,
        input_data: Optional[Dict[str, Any]] = None,
        dependencies: Optional[List[str]] = None,
        actor: str = "task_router",
        raise_errors: bool = False,
    ) -> tuple[InvestigationTask, TaskRouteDecision]:
        """
        Create a new unassigned task, add it to the context, and route it.
        """

        task = InvestigationTask(
            task_type=self._normalize_task_type(
                task_type
            ),
            assigned_agent="unassigned",
            description=description,
            priority=priority,
            input_data=input_data or {},
            dependencies=dependencies or [],
        )

        self.context.add_task(
            task=task,
            actor=actor,
        )

        decision = self.route_task(
            task=task,
            force_reassign=True,
            raise_errors=raise_errors,
        )

        return task, decision

    def execute_task(
        self,
        task: InvestigationTask,
        auto_route: bool = True,
        raise_errors: bool = False,
    ):
        """
        Execute a task using its assigned agent.

        If auto_route=True, the task is routed before execution when its
        current assignment is unavailable or invalid.
        """

        if not isinstance(task, InvestigationTask):
            raise TypeError(
                "task must be an InvestigationTask instance."
            )

        assigned_agent = self.get_agent(
            task.assigned_agent
        )

        assignment_valid = (
            assigned_agent is not None
            and assigned_agent.supports_task(
                task.task_type
            )
        )

        if not assignment_valid and auto_route:
            decision = self.route_task(
                task=task,
                force_reassign=True,
                raise_errors=raise_errors,
            )

            if not decision.success:
                return None

            assigned_agent = self.get_agent(
                decision.selected_agent or ""
            )

        if assigned_agent is None:
            message = (
                f"No registered agent is available for task "
                f"{task.task_id}."
            )

            if raise_errors:
                raise TaskRoutingError(message)

            return None

        return assigned_agent.run_task(
            task=task,
            raise_errors=raise_errors,
        )

    def execute_all_ready_tasks(
        self,
        raise_errors: bool = False,
    ) -> List[Any]:
        """
        Route and execute all currently ready pending tasks.

        The ready-task list is recalculated after each execution so
        dependency chains can progress.
        """

        results: List[Any] = []
        attempted_task_ids: Set[str] = set()

        while True:
            ready_tasks = [
                task
                for task in self.context.get_ready_tasks()
                if task.task_id not in attempted_task_ids
            ]

            if not ready_tasks:
                break

            task = ready_tasks[0]
            attempted_task_ids.add(task.task_id)

            result = self.execute_task(
                task=task,
                auto_route=True,
                raise_errors=raise_errors,
            )

            if result is not None:
                results.append(result)

        return results

    def get_routing_history(
        self,
        task_id: Optional[str] = None,
        successful_only: bool = False,
    ) -> List[TaskRouteDecision]:
        """Return routing history with optional filters."""

        decisions = list(self._routing_history)

        if task_id is not None:
            decisions = [
                decision
                for decision in decisions
                if decision.task_id == task_id
            ]

        if successful_only:
            decisions = [
                decision
                for decision in decisions
                if decision.success
            ]

        return decisions

    def get_capability_map(self) -> Dict[str, List[str]]:
        """Return the current task-type-to-agent mapping."""

        return {
            task_type: sorted(agent_names)
            for task_type, agent_names
            in sorted(self._capability_map.items())
        }

    def get_router_status(self) -> Dict[str, Any]:
        """Return a compact task-router status report."""

        return {
            "registered_agent_count": len(
                self._agents
            ),
            "registered_agents": self.get_agent_names(),
            "capability_count": len(
                self._capability_map
            ),
            "capability_map": self.get_capability_map(),
            "routing_decision_count": len(
                self._routing_history
            ),
            "successful_routing_count": sum(
                1
                for decision in self._routing_history
                if decision.success
            ),
            "failed_routing_count": sum(
                1
                for decision in self._routing_history
                if not decision.success
            ),
        }