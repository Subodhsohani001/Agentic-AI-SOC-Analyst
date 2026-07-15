from __future__ import annotations

from typing import Any

from .response_models import (
    ActionStatus,
    ActionType,
    PolicyDecision,
    ResponseAction,
    ResponsePlan,
)


class ResponsePlanner:
    """
    Converts a deterministic PolicyDecision into an ordered ResponsePlan.

    Responsibilities:
    - Resolve targets for every recommended action
    - Apply deterministic execution ordering
    - Mark destructive actions as requiring human approval
    - Keep all response actions in simulation mode by default
    - Safely skip actions when their required target is unavailable
    """

    DESTRUCTIVE_ACTIONS = {
        ActionType.BLOCK_IP,
        ActionType.ISOLATE_HOST,
        ActionType.DISABLE_USER,
        ActionType.RESET_PASSWORD,
    }

    ACTION_ORDER = {
        ActionType.CREATE_TICKET: 10,
        ActionType.NOTIFY_SOC: 20,
        ActionType.COLLECT_FORENSICS: 30,
        ActionType.BLOCK_IP: 40,
        ActionType.ISOLATE_HOST: 50,
        ActionType.DISABLE_USER: 60,
        ActionType.RESET_PASSWORD: 70,
        ActionType.MONITOR: 80,
        ActionType.NO_ACTION: 90,
    }

    def __init__(
        self,
        simulation_mode: bool = True,
    ) -> None:
        """
        Initialize the response planner.

        Args:
            simulation_mode:
                True keeps generated response actions non-destructive.
                This should remain enabled during v0.6.0 development.
        """

        self.simulation_mode = simulation_mode

    def build_plan(
        self,
        incident_id: str,
        decision: PolicyDecision,
        incident: dict[str, Any],
    ) -> ResponsePlan:
        """
        Build an ordered ResponsePlan from a PolicyDecision.

        Args:
            incident_id:
                Unique incident identifier.

            decision:
                Deterministic response decision produced by
                ResponsePolicyEngine.

            incident:
                Original incident data containing IOCs, users, hosts,
                intelligence evidence, and historical correlation.

        Returns:
            ResponsePlan containing ordered ResponseAction objects.
        """

        incident_id = self._normalize_text(
            incident_id,
            default="INC-UNKNOWN",
        )

        ip_addresses = self._extract_ip_addresses(incident)
        usernames = self._extract_usernames(incident)
        hostnames = self._extract_hostnames(incident)

        ordered_action_types = sorted(
            decision.recommended_actions,
            key=lambda action: self.ACTION_ORDER.get(action, 999),
        )

        actions: list[ResponseAction] = []

        for action_type in ordered_action_types:
            action = self._create_action(
                action_type=action_type,
                incident_id=incident_id,
                decision=decision,
                ip_addresses=ip_addresses,
                usernames=usernames,
                hostnames=hostnames,
            )

            actions.append(action)

        plan = ResponsePlan(
            incident_id=incident_id,
            priority=decision.priority,
            actions=actions,
            summary=self._build_summary(
                incident_id=incident_id,
                decision=decision,
                actions=actions,
            ),
        )

        plan.update_status()

        return plan

    def _create_action(
        self,
        action_type: ActionType,
        incident_id: str,
        decision: PolicyDecision,
        ip_addresses: list[str],
        usernames: list[str],
        hostnames: list[str],
    ) -> ResponseAction:
        """
        Create one response action with its target and approval policy.
        """

        target = self._resolve_target(
            action_type=action_type,
            incident_id=incident_id,
            ip_addresses=ip_addresses,
            usernames=usernames,
            hostnames=hostnames,
        )

        reason = self._build_action_reason(
            action_type=action_type,
            decision=decision,
        )

        requires_approval = action_type in self.DESTRUCTIVE_ACTIONS

        action = ResponseAction(
            action_type=action_type,
            target=target or "unresolved",
            reason=reason,
            requires_approval=requires_approval,
            simulation_mode=self.simulation_mode,
        )

        if requires_approval:
            action.status = ActionStatus.AWAITING_APPROVAL

        if target is None:
            action.status = ActionStatus.SKIPPED
            action.error = (
                f"No valid target was available for "
                f"{action_type.value}."
            )

        return action

    def _resolve_target(
        self,
        action_type: ActionType,
        incident_id: str,
        ip_addresses: list[str],
        usernames: list[str],
        hostnames: list[str],
    ) -> str | None:
        """
        Resolve the most appropriate target for an action.
        """

        if action_type == ActionType.BLOCK_IP:
            return ip_addresses[0] if ip_addresses else None

        if action_type == ActionType.ISOLATE_HOST:
            return hostnames[0] if hostnames else None

        if action_type in {
            ActionType.DISABLE_USER,
            ActionType.RESET_PASSWORD,
        }:
            return usernames[0] if usernames else None

        if action_type == ActionType.COLLECT_FORENSICS:
            if hostnames:
                return hostnames[0]

            if ip_addresses:
                return ip_addresses[0]

            return incident_id

        if action_type == ActionType.CREATE_TICKET:
            return incident_id

        if action_type == ActionType.NOTIFY_SOC:
            return "SOC_TEAM"

        if action_type == ActionType.MONITOR:
            if ip_addresses:
                return ip_addresses[0]

            if hostnames:
                return hostnames[0]

            if usernames:
                return usernames[0]

            return incident_id

        if action_type == ActionType.NO_ACTION:
            return incident_id

        return incident_id

    def _build_action_reason(
        self,
        action_type: ActionType,
        decision: PolicyDecision,
    ) -> str:
        """
        Generate an analyst-readable reason for an action.
        """

        base_reason = {
            ActionType.BLOCK_IP:
                "Contain confirmed or highly suspicious network activity.",

            ActionType.ISOLATE_HOST:
                "Prevent additional execution, propagation, or data loss.",

            ActionType.DISABLE_USER:
                "Contain possible account compromise or credential abuse.",

            ActionType.RESET_PASSWORD:
                "Invalidate potentially exposed user credentials.",

            ActionType.CREATE_TICKET:
                "Track investigation, ownership, evidence, and remediation.",

            ActionType.NOTIFY_SOC:
                "Escalate the incident to the responsible SOC team.",

            ActionType.COLLECT_FORENSICS:
                "Preserve evidence for investigation and incident scoping.",

            ActionType.MONITOR:
                "Continue observing the entity for additional activity.",

            ActionType.NO_ACTION:
                "No active containment is required under current policy.",
        }.get(
            action_type,
            "Execute the response action selected by policy.",
        )

        return (
            f"{base_reason} "
            f"Decision priority: {decision.priority.value}; "
            f"risk score: {decision.risk_score}; "
            f"severity: {decision.severity}."
        )

    def _build_summary(
        self,
        incident_id: str,
        decision: PolicyDecision,
        actions: list[ResponseAction],
    ) -> str:
        """
        Build a compact response-plan summary.
        """

        executable_count = sum(
            action.status != ActionStatus.SKIPPED
            for action in actions
        )

        approval_count = sum(
            action.requires_approval
            and action.status != ActionStatus.SKIPPED
            for action in actions
        )

        skipped_count = sum(
            action.status == ActionStatus.SKIPPED
            for action in actions
        )

        return (
            f"Response plan for {incident_id}: "
            f"{executable_count} executable action(s), "
            f"{approval_count} approval-controlled action(s), "
            f"{skipped_count} skipped action(s). "
            f"Priority {decision.priority.value}, "
            f"risk score {decision.risk_score}."
        )

    def _extract_ip_addresses(
        self,
        incident: dict[str, Any],
    ) -> list[str]:
        candidates = [
            incident.get("source_ip"),
            incident.get("ip_addresses"),
            incident.get("ips"),
            self._nested_get(
                incident,
                "indicators_of_compromise",
                "ips",
            ),
            self._nested_get(
                incident,
                "iocs",
                "ips",
            ),
        ]

        return self._flatten_strings(candidates)

    def _extract_usernames(
        self,
        incident: dict[str, Any],
    ) -> list[str]:
        candidates = [
            incident.get("username"),
            incident.get("user"),
            incident.get("users"),
            incident.get("affected_users"),
            self._nested_get(
                incident,
                "extracted_facts",
                "users",
            ),
        ]

        return self._flatten_strings(candidates)

    def _extract_hostnames(
        self,
        incident: dict[str, Any],
    ) -> list[str]:
        candidates = [
            incident.get("hostname"),
            incident.get("host"),
            incident.get("hosts"),
            incident.get("affected_hosts"),
            self._nested_get(
                incident,
                "extracted_facts",
                "hosts",
            ),
        ]

        return self._flatten_strings(candidates)

    @staticmethod
    def _nested_get(
        data: dict[str, Any],
        *keys: str,
    ) -> Any:
        current: Any = data

        for key in keys:
            if not isinstance(current, dict):
                return None

            current = current.get(key)

        return current

    @staticmethod
    def _flatten_strings(
        values: list[Any],
    ) -> list[str]:
        result: list[str] = []

        for value in values:
            if value is None:
                continue

            if isinstance(value, str):
                cleaned = value.strip()

                if cleaned and cleaned not in result:
                    result.append(cleaned)

            elif isinstance(value, list):
                for item in value:
                    if not isinstance(item, str):
                        continue

                    cleaned = item.strip()

                    if cleaned and cleaned not in result:
                        result.append(cleaned)

        return result

    @staticmethod
    def _normalize_text(
        value: Any,
        default: str = "",
    ) -> str:
        if value is None:
            return default

        text = str(value).strip()

        return text if text else default