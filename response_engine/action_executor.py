from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from .response_models import (
    ActionStatus,
    ActionType,
    ResponseAction,
    ResponsePlan,
)


class ActionExecutor:
    """
    Executes response actions in simulation mode.

    v0.6.0 safety rules:
    - No real firewall, EDR, identity, or host changes
    - Approval-controlled actions execute only after approval
    - Rejected, skipped, completed, and failed actions are not re-executed
    - Every execution returns structured evidence
    """

    TERMINAL_STATUSES = {
        ActionStatus.SUCCESS,
        ActionStatus.SIMULATED,
        ActionStatus.FAILED,
        ActionStatus.SKIPPED,
        ActionStatus.REJECTED,
    }

    def __init__(
        self,
        simulation_mode: bool = True,
    ) -> None:
        self.simulation_mode = simulation_mode

        self._handlers: dict[
            ActionType,
            Callable[[ResponseAction, str], dict[str, Any]],
        ] = {
            ActionType.BLOCK_IP: self._simulate_block_ip,
            ActionType.ISOLATE_HOST: self._simulate_isolate_host,
            ActionType.DISABLE_USER: self._simulate_disable_user,
            ActionType.RESET_PASSWORD: self._simulate_reset_password,
            ActionType.CREATE_TICKET: self._simulate_create_ticket,
            ActionType.NOTIFY_SOC: self._simulate_notify_soc,
            ActionType.COLLECT_FORENSICS:
                self._simulate_collect_forensics,
            ActionType.MONITOR: self._simulate_monitor,
            ActionType.NO_ACTION: self._simulate_no_action,
        }

    def execute_plan(
        self,
        plan: ResponsePlan,
        actor: str = "agentic_soc_analyst",
    ) -> list[dict[str, Any]]:
        """
        Execute all eligible actions in their existing plan order.

        Returns one structured result per action.
        """

        execution_results: list[dict[str, Any]] = []

        plan.status = "running"

        for action in plan.actions:
            execution_results.append(
                self.execute_action(
                    action=action,
                    incident_id=plan.incident_id,
                    actor=actor,
                )
            )

        plan.update_status()

        return execution_results

    def execute_action(
        self,
        action: ResponseAction,
        incident_id: str,
        actor: str = "agentic_soc_analyst",
    ) -> dict[str, Any]:
        """
        Execute one eligible response action.
        """

        if action.status in self.TERMINAL_STATUSES:
            return self._build_skipped_result(
                action=action,
                reason=(
                    f"Action is already in terminal state "
                    f"{action.status.value}."
                ),
            )

        if (
            action.requires_approval
            and action.status != ActionStatus.APPROVED
        ):
            return self._build_skipped_result(
                action=action,
                reason="Action requires analyst approval before execution.",
            )

        if (
            not action.requires_approval
            and action.status not in {
                ActionStatus.PENDING,
                ActionStatus.APPROVED,
            }
        ):
            return self._build_skipped_result(
                action=action,
                reason=(
                    f"Action cannot execute from state "
                    f"{action.status.value}."
                ),
            )

        handler = self._handlers.get(action.action_type)

        if handler is None:
            action.mark_failed(
                f"No execution handler exists for "
                f"{action.action_type.value}."
            )

            return {
                "action_id": action.action_id,
                "action_type": action.action_type.value,
                "target": action.target,
                "status": action.status.value,
                "error": action.error,
            }

        try:
            action.mark_running()

            execution_result = handler(
                action,
                incident_id,
            )

            existing_result = dict(action.result)

            action.simulation_mode = self.simulation_mode
            action.mark_success(execution_result)

            if existing_result:
                action.result = {
                    **existing_result,
                    **action.result,
                }

            action.result["actor"] = actor

            return {
                "action_id": action.action_id,
                "action_type": action.action_type.value,
                "target": action.target,
                "status": action.status.value,
                "result": action.result,
            }

        except Exception as exc:
            action.mark_failed(str(exc))

            return {
                "action_id": action.action_id,
                "action_type": action.action_type.value,
                "target": action.target,
                "status": action.status.value,
                "error": action.error,
            }

    def register_handler(
        self,
        action_type: ActionType,
        handler: Callable[
            [ResponseAction, str],
            dict[str, Any],
        ],
    ) -> None:
        """
        Register or replace an action handler.

        This enables later integration with real SOAR connectors.
        """

        if not callable(handler):
            raise TypeError("Handler must be callable.")

        self._handlers[action_type] = handler

    def _simulate_block_ip(
        self,
        action: ResponseAction,
        incident_id: str,
    ) -> dict[str, Any]:
        self._validate_target(action)

        return self._simulation_result(
            action=action,
            incident_id=incident_id,
            message=(
                f"Simulated firewall block for IP "
                f"{action.target}."
            ),
            provider="simulated_firewall",
            artifact={
                "rule_name": f"BLOCK-{incident_id}-{action.target}",
                "direction": "both",
                "duration": "until_manual_review",
            },
        )

    def _simulate_isolate_host(
        self,
        action: ResponseAction,
        incident_id: str,
    ) -> dict[str, Any]:
        self._validate_target(action)

        return self._simulation_result(
            action=action,
            incident_id=incident_id,
            message=(
                f"Simulated endpoint isolation for host "
                f"{action.target}."
            ),
            provider="simulated_edr",
            artifact={
                "network_access": "restricted",
                "management_channel": "preserved",
            },
        )

    def _simulate_disable_user(
        self,
        action: ResponseAction,
        incident_id: str,
    ) -> dict[str, Any]:
        self._validate_target(action)

        return self._simulation_result(
            action=action,
            incident_id=incident_id,
            message=(
                f"Simulated account disablement for "
                f"{action.target}."
            ),
            provider="simulated_identity_provider",
            artifact={
                "account_status": "disabled",
                "sessions_revoked": True,
            },
        )

    def _simulate_reset_password(
        self,
        action: ResponseAction,
        incident_id: str,
    ) -> dict[str, Any]:
        self._validate_target(action)

        return self._simulation_result(
            action=action,
            incident_id=incident_id,
            message=(
                f"Simulated forced password reset for "
                f"{action.target}."
            ),
            provider="simulated_identity_provider",
            artifact={
                "password_reset_required": True,
                "sessions_revoked": True,
            },
        )

    def _simulate_create_ticket(
        self,
        action: ResponseAction,
        incident_id: str,
    ) -> dict[str, Any]:
        self._validate_target(action)

        return self._simulation_result(
            action=action,
            incident_id=incident_id,
            message=(
                f"Simulated ticket creation for "
                f"{incident_id}."
            ),
            provider="simulated_ticketing",
            artifact={
                "incident_id": incident_id,
                "ticket_status": "open",
            },
        )

    def _simulate_notify_soc(
        self,
        action: ResponseAction,
        incident_id: str,
    ) -> dict[str, Any]:
        self._validate_target(action)

        return self._simulation_result(
            action=action,
            incident_id=incident_id,
            message=(
                f"Simulated notification sent to "
                f"{action.target}."
            ),
            provider="simulated_notification_service",
            artifact={
                "channel": "soc_alert_queue",
                "delivery_status": "delivered",
            },
        )

    def _simulate_collect_forensics(
        self,
        action: ResponseAction,
        incident_id: str,
    ) -> dict[str, Any]:
        self._validate_target(action)

        return self._simulation_result(
            action=action,
            incident_id=incident_id,
            message=(
                f"Simulated forensic collection from "
                f"{action.target}."
            ),
            provider="simulated_forensics_collector",
            artifact={
                "collection_types": [
                    "process_list",
                    "network_connections",
                    "event_logs",
                ],
                "evidence_reference": (
                    f"EVID-{incident_id}-{action.action_id}"
                ),
            },
        )

    def _simulate_monitor(
        self,
        action: ResponseAction,
        incident_id: str,
    ) -> dict[str, Any]:
        self._validate_target(action)

        return self._simulation_result(
            action=action,
            incident_id=incident_id,
            message=(
                f"Simulated enhanced monitoring enabled for "
                f"{action.target}."
            ),
            provider="simulated_siem",
            artifact={
                "monitoring_window_hours": 24,
                "alerting_enabled": True,
            },
        )

    def _simulate_no_action(
        self,
        action: ResponseAction,
        incident_id: str,
    ) -> dict[str, Any]:
        return self._simulation_result(
            action=action,
            incident_id=incident_id,
            message=(
                "No containment action performed under current policy."
            ),
            provider="policy_engine",
            artifact={
                "decision": "no_action",
            },
        )

    def _simulation_result(
        self,
        action: ResponseAction,
        incident_id: str,
        message: str,
        provider: str,
        artifact: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "mode": (
                "simulation"
                if self.simulation_mode
                else "live"
            ),
            "incident_id": incident_id,
            "provider": provider,
            "message": message,
            "artifact": artifact,
            "executed_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "action_type": action.action_type.value,
            "target": action.target,
        }

    @staticmethod
    def _validate_target(
        action: ResponseAction,
    ) -> None:
        target = str(action.target).strip()

        if not target or target.lower() == "unresolved":
            raise ValueError(
                f"Cannot execute {action.action_type.value}: "
                f"target is unresolved."
            )

    @staticmethod
    def _build_skipped_result(
        action: ResponseAction,
        reason: str,
    ) -> dict[str, Any]:
        return {
            "action_id": action.action_id,
            "action_type": action.action_type.value,
            "target": action.target,
            "status": action.status.value,
            "executed": False,
            "reason": reason,
        }