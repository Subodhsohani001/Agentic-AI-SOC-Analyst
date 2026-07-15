from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class ActionType(str, Enum):
    """Supported response actions."""

    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    DISABLE_USER = "disable_user"
    RESET_PASSWORD = "reset_password"
    CREATE_TICKET = "create_ticket"
    NOTIFY_SOC = "notify_soc"
    COLLECT_FORENSICS = "collect_forensics"
    MONITOR = "monitor"
    NO_ACTION = "no_action"


class ActionStatus(str, Enum):
    """Execution state of a response action."""

    PENDING = "pending"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SIMULATED = "simulated"
    SKIPPED = "skipped"


class ApprovalStatus(str, Enum):
    """Human approval state."""

    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ResponsePriority(str, Enum):
    """SOC response priority."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


@dataclass
class ResponseAction:
    """
    Represents one response action inside a response plan.

    Example:
        Block IP 185.220.101.45 in simulation mode.
    """

    action_type: ActionType
    target: str
    reason: str

    action_id: str = field(
        default_factory=lambda: f"ACT-{uuid4().hex[:10].upper()}"
    )

    status: ActionStatus = ActionStatus.PENDING
    requires_approval: bool = True
    simulation_mode: bool = True

    command: str | None = None
    result: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    executed_at: str | None = None

    def mark_running(self) -> None:
        self.status = ActionStatus.RUNNING

    def mark_success(self, result: dict[str, Any] | None = None) -> None:
        self.status = (
            ActionStatus.SIMULATED
            if self.simulation_mode
            else ActionStatus.SUCCESS
        )

        self.result = result or {}
        self.error = None
        self.executed_at = datetime.now(timezone.utc).isoformat()

    def mark_failed(self, error: str) -> None:
        self.status = ActionStatus.FAILED
        self.error = error
        self.executed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyDecision:
    """
    Deterministic decision produced by the policy engine.
    """

    severity: str
    risk_score: int
    confidence: str
    priority: ResponsePriority

    recommended_actions: list[ActionType]

    decision_id: str = field(
        default_factory=lambda: f"DEC-{uuid4().hex[:10].upper()}"
    )

    rationale: list[str] = field(default_factory=list)
    matched_policies: list[str] = field(default_factory=list)

    requires_human_approval: bool = True
    automatic_execution_allowed: bool = False

    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        self.risk_score = max(0, min(int(self.risk_score), 100))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ResponsePlan:
    """
    Ordered response workflow generated from a policy decision.
    """

    incident_id: str
    priority: ResponsePriority
    actions: list[ResponseAction]

    plan_id: str = field(
        default_factory=lambda: f"PLAN-{uuid4().hex[:10].upper()}"
    )

    summary: str = ""
    status: str = "pending"

    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    completed_at: str | None = None

    def get_pending_actions(self) -> list[ResponseAction]:
        return [
            action
            for action in self.actions
            if action.status
            in {
                ActionStatus.PENDING,
                ActionStatus.AWAITING_APPROVAL,
                ActionStatus.APPROVED,
            }
        ]

    def get_failed_actions(self) -> list[ResponseAction]:
        return [
            action
            for action in self.actions
            if action.status == ActionStatus.FAILED
        ]

    def update_status(self) -> str:
        if not self.actions:
            self.status = "empty"
            return self.status

        statuses = {action.status for action in self.actions}

        if ActionStatus.RUNNING in statuses:
            self.status = "running"

        elif ActionStatus.FAILED in statuses:
            self.status = "failed"

        elif statuses.issubset(
            {
                ActionStatus.SUCCESS,
                ActionStatus.SIMULATED,
                ActionStatus.SKIPPED,
                ActionStatus.REJECTED,
            }
        ):
            self.status = "completed"
            self.completed_at = datetime.now(timezone.utc).isoformat()

        elif ActionStatus.AWAITING_APPROVAL in statuses:
            self.status = "awaiting_approval"

        else:
            self.status = "pending"

        return self.status

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ApprovalRequest:
    """
    Represents a human-in-the-loop approval request.
    """

    action_id: str
    incident_id: str
    requested_action: ActionType
    target: str
    reason: str

    approval_id: str = field(
        default_factory=lambda: f"APR-{uuid4().hex[:10].upper()}"
    )

    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_by: str = "agentic_soc_analyst"
    reviewed_by: str | None = None
    review_comment: str | None = None

    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    reviewed_at: str | None = None

    def approve(
        self,
        reviewed_by: str,
        comment: str | None = None,
    ) -> None:
        self.status = ApprovalStatus.APPROVED
        self.reviewed_by = reviewed_by
        self.review_comment = comment
        self.reviewed_at = datetime.now(timezone.utc).isoformat()

    def reject(
        self,
        reviewed_by: str,
        comment: str | None = None,
    ) -> None:
        self.status = ApprovalStatus.REJECTED
        self.reviewed_by = reviewed_by
        self.review_comment = comment
        self.reviewed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditEvent:
    """
    Immutable-style audit record for a response operation.
    """

    event_type: str
    action: str
    actor: str
    status: str

    event_id: str = field(
        default_factory=lambda: f"AUD-{uuid4().hex[:10].upper()}"
    )

    incident_id: str | None = None
    action_id: str | None = None
    target: str | None = None
    reason: str | None = None

    metadata: dict[str, Any] = field(default_factory=dict)

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)