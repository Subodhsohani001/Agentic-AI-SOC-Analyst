from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from .response_models import (
    ApprovalRequest,
    AuditEvent,
    ResponseAction,
    ResponsePlan,
)


class AuditLogger:
    """
    Append-only audit logger for response orchestration.

    Responsibilities:
    - Record policy, planning, approval, ticket, and execution events
    - Persist events as JSON Lines
    - Keep an in-memory event collection
    - Support filtering by incident, action, actor, status, or event type
    - Never overwrite previous audit entries
    """

    def __init__(
        self,
        log_path: str | Path = "response_engine/audit/audit_log.jsonl",
    ) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._events: list[AuditEvent] = []
        self._lock = Lock()

        self._load_existing_events()

    def log_event(
        self,
        event_type: str,
        action: str,
        actor: str,
        status: str,
        incident_id: str | None = None,
        action_id: str | None = None,
        target: str | None = None,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """
        Create and persist one audit event.
        """

        event = AuditEvent(
            event_type=self._normalize_required(
                event_type,
                "event_type",
            ),
            action=self._normalize_required(
                action,
                "action",
            ),
            actor=self._normalize_required(
                actor,
                "actor",
            ),
            status=self._normalize_required(
                status,
                "status",
            ),
            incident_id=self._normalize_optional(incident_id),
            action_id=self._normalize_optional(action_id),
            target=self._normalize_optional(target),
            reason=self._normalize_optional(reason),
            metadata=metadata or {},
        )

        self._append_event(event)

        return event

    def log_plan_created(
        self,
        plan: ResponsePlan,
        actor: str = "agentic_soc_analyst",
    ) -> AuditEvent:
        """
        Record response-plan creation.
        """

        return self.log_event(
            event_type="response_plan",
            action="create_plan",
            actor=actor,
            status=plan.status,
            incident_id=plan.incident_id,
            reason=plan.summary,
            metadata={
                "plan_id": plan.plan_id,
                "priority": plan.priority.value,
                "action_count": len(plan.actions),
                "actions": [
                    action.action_type.value
                    for action in plan.actions
                ],
            },
        )

    def log_approval_requested(
        self,
        request: ApprovalRequest,
    ) -> AuditEvent:
        """
        Record creation of an approval request.
        """

        return self.log_event(
            event_type="approval",
            action="request_approval",
            actor=request.requested_by,
            status=request.status.value,
            incident_id=request.incident_id,
            action_id=request.action_id,
            target=request.target,
            reason=request.reason,
            metadata={
                "approval_id": request.approval_id,
                "requested_action":
                    request.requested_action.value,
                "created_at": request.created_at,
            },
        )

    def log_approval_reviewed(
        self,
        request: ApprovalRequest,
    ) -> AuditEvent:
        """
        Record approval, rejection, or expiration.
        """

        return self.log_event(
            event_type="approval",
            action=f"approval_{request.status.value}",
            actor=request.reviewed_by or "system",
            status=request.status.value,
            incident_id=request.incident_id,
            action_id=request.action_id,
            target=request.target,
            reason=request.review_comment or request.reason,
            metadata={
                "approval_id": request.approval_id,
                "requested_action":
                    request.requested_action.value,
                "requested_by": request.requested_by,
                "reviewed_at": request.reviewed_at,
            },
        )

    def log_action_execution(
        self,
        action: ResponseAction,
        incident_id: str,
        actor: str = "agentic_soc_analyst",
    ) -> AuditEvent:
        """
        Record the final state of one response action.
        """

        return self.log_event(
            event_type="response_action",
            action=action.action_type.value,
            actor=actor,
            status=action.status.value,
            incident_id=incident_id,
            action_id=action.action_id,
            target=action.target,
            reason=action.reason,
            metadata={
                "requires_approval":
                    action.requires_approval,
                "simulation_mode":
                    action.simulation_mode,
                "result":
                    action.result,
                "error":
                    action.error,
                "created_at":
                    action.created_at,
                "executed_at":
                    action.executed_at,
            },
        )

    def log_plan_completed(
        self,
        plan: ResponsePlan,
        actor: str = "agentic_soc_analyst",
    ) -> AuditEvent:
        """
        Record final response-plan status.
        """

        status_counts: dict[str, int] = {}

        for action in plan.actions:
            key = action.status.value
            status_counts[key] = status_counts.get(key, 0) + 1

        return self.log_event(
            event_type="response_plan",
            action="complete_plan",
            actor=actor,
            status=plan.status,
            incident_id=plan.incident_id,
            reason=plan.summary,
            metadata={
                "plan_id": plan.plan_id,
                "completed_at": plan.completed_at,
                "status_counts": status_counts,
            },
        )

    def list_events(
        self,
        incident_id: str | None = None,
        action_id: str | None = None,
        actor: str | None = None,
        status: str | None = None,
        event_type: str | None = None,
    ) -> list[AuditEvent]:
        """
        Return audit events using optional filters.
        """

        events = list(self._events)

        if incident_id is not None:
            events = [
                event
                for event in events
                if event.incident_id == incident_id
            ]

        if action_id is not None:
            events = [
                event
                for event in events
                if event.action_id == action_id
            ]

        if actor is not None:
            normalized_actor = actor.strip().lower()

            events = [
                event
                for event in events
                if event.actor.strip().lower()
                == normalized_actor
            ]

        if status is not None:
            normalized_status = status.strip().lower()

            events = [
                event
                for event in events
                if event.status.strip().lower()
                == normalized_status
            ]

        if event_type is not None:
            normalized_event_type = (
                event_type.strip().lower()
            )

            events = [
                event
                for event in events
                if event.event_type.strip().lower()
                == normalized_event_type
            ]

        return events

    def export_events(
        self,
    ) -> list[dict[str, Any]]:
        """
        Export all events as dictionaries.
        """

        return [
            event.to_dict()
            for event in self._events
        ]

    def get_event_count(
        self,
    ) -> int:
        return len(self._events)

    def _append_event(
        self,
        event: AuditEvent,
    ) -> None:
        """
        Persist one event atomically as a JSONL record.
        """

        serialized = self._serialize_event(event)

        with self._lock:
            with self.log_path.open(
                "a",
                encoding="utf-8",
            ) as file:
                file.write(
                    json.dumps(
                        serialized,
                        ensure_ascii=False,
                    )
                )
                file.write("\n")

            self._events.append(event)

    def _load_existing_events(
        self,
    ) -> None:
        """
        Load valid existing JSONL audit events.
        """

        if not self.log_path.exists():
            return

        try:
            with self.log_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                for line in file:
                    cleaned = line.strip()

                    if not cleaned:
                        continue

                    try:
                        data = json.loads(cleaned)

                        event = AuditEvent(
                            event_type=data["event_type"],
                            action=data["action"],
                            actor=data["actor"],
                            status=data["status"],
                            event_id=data["event_id"],
                            incident_id=data.get("incident_id"),
                            action_id=data.get("action_id"),
                            target=data.get("target"),
                            reason=data.get("reason"),
                            metadata=data.get(
                                "metadata",
                                {},
                            ),
                            timestamp=data.get(
                                "timestamp",
                                datetime.now(
                                    timezone.utc
                                ).isoformat(),
                            ),
                        )

                        self._events.append(event)

                    except (
                        json.JSONDecodeError,
                        KeyError,
                        TypeError,
                    ):
                        continue

        except OSError:
            return

    @staticmethod
    def _serialize_event(
        event: AuditEvent,
    ) -> dict[str, Any]:
        """
        Convert an audit event into JSON-safe data.
        """

        return {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "action": event.action,
            "actor": event.actor,
            "status": event.status,
            "incident_id": event.incident_id,
            "action_id": event.action_id,
            "target": event.target,
            "reason": event.reason,
            "metadata": event.metadata,
            "timestamp": event.timestamp,
        }

    @staticmethod
    def _normalize_required(
        value: Any,
        field_name: str,
    ) -> str:
        text = str(value).strip()

        if not text:
            raise ValueError(
                f"{field_name} cannot be empty."
            )

        return text

    @staticmethod
    def _normalize_optional(
        value: Any,
    ) -> str | None:
        if value is None:
            return None

        text = str(value).strip()

        return text or None