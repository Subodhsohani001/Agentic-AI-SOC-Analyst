from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .response_models import (
    ActionStatus,
    ActionType,
    ResponseAction,
    ResponsePlan,
    ResponsePriority,
)


@dataclass
class SOCTicket:
    """
    Structured SOC incident ticket.

    This represents an internal simulated ticket during v0.6.0.
    Later versions can integrate ServiceNow, Jira, TheHive, or another
    external ticketing platform.
    """

    incident_id: str
    title: str
    description: str
    priority: ResponsePriority

    ticket_id: str = field(
        default_factory=lambda: f"TKT-{uuid4().hex[:10].upper()}"
    )

    status: str = "open"
    category: str = "security_incident"
    assigned_team: str = "SOC_L1"
    assigned_to: str | None = None

    severity: str = "UNKNOWN"
    risk_score: int = 0
    confidence: str = "Unknown"

    observables: dict[str, list[str]] = field(default_factory=dict)
    mitre_techniques: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)

    evidence: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    closed_at: str | None = None

    def assign(
        self,
        analyst: str,
        team: str | None = None,
    ) -> None:
        """
        Assign the ticket to an analyst and optionally change the team.
        """

        cleaned_analyst = str(analyst).strip()

        if not cleaned_analyst:
            raise ValueError("Analyst name cannot be empty.")

        self.assigned_to = cleaned_analyst

        if team:
            cleaned_team = str(team).strip()

            if cleaned_team:
                self.assigned_team = cleaned_team

        self.status = "assigned"
        self._touch()

    def update_status(
        self,
        status: str,
    ) -> None:
        """
        Update ticket lifecycle status.
        """

        allowed_statuses = {
            "open",
            "assigned",
            "investigating",
            "contained",
            "resolved",
            "closed",
            "rejected",
        }

        normalized_status = str(status).strip().lower()

        if normalized_status not in allowed_statuses:
            raise ValueError(
                f"Unsupported ticket status: {normalized_status}"
            )

        self.status = normalized_status

        if normalized_status == "closed":
            self.closed_at = datetime.now(timezone.utc).isoformat()

        self._touch()

    def add_evidence(
        self,
        evidence: str,
    ) -> None:
        """
        Attach an evidence reference or analyst note.
        """

        cleaned = str(evidence).strip()

        if cleaned and cleaned not in self.evidence:
            self.evidence.append(cleaned)
            self._touch()

    def add_tag(
        self,
        tag: str,
    ) -> None:
        """
        Add a searchable ticket tag.
        """

        cleaned = str(tag).strip().lower()

        if cleaned and cleaned not in self.tags:
            self.tags.append(cleaned)
            self._touch()

    def _touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TicketManager:
    """
    Creates and manages simulated SOC tickets.

    Responsibilities:
    - Convert incident and response-plan data into structured tickets
    - Maintain tickets in memory during runtime
    - Update the matching CREATE_TICKET response action
    - Provide deterministic assignment and lifecycle operations
    """

    PRIORITY_TEAM_MAPPING = {
        ResponsePriority.P1: "SOC_L2",
        ResponsePriority.P2: "SOC_L2",
        ResponsePriority.P3: "SOC_L1",
        ResponsePriority.P4: "SOC_L1",
    }

    def __init__(self) -> None:
        self._tickets: dict[str, SOCTicket] = {}

    def create_ticket(
        self,
        incident: dict[str, Any],
        plan: ResponsePlan,
    ) -> SOCTicket:
        """
        Create a structured SOC ticket from an incident and response plan.
        """

        severity = self._normalize_text(
            incident.get("severity"),
            default="UNKNOWN",
        ).upper()

        confidence = self._normalize_text(
            incident.get("confidence"),
            default="Unknown",
        )

        risk_score = self._extract_risk_score(incident)
        observables = self._extract_observables(incident)
        mitre_techniques = self._extract_mitre_ids(incident)

        recommended_actions = [
            action.action_type.value
            for action in plan.actions
            if action.action_type != ActionType.NO_ACTION
        ]

        ticket = SOCTicket(
            incident_id=plan.incident_id,
            title=self._build_title(
                incident=incident,
                severity=severity,
            ),
            description=self._build_description(
                incident=incident,
                plan=plan,
                severity=severity,
                risk_score=risk_score,
                confidence=confidence,
            ),
            priority=plan.priority,
            assigned_team=self.PRIORITY_TEAM_MAPPING.get(
                plan.priority,
                "SOC_L1",
            ),
            severity=severity,
            risk_score=risk_score,
            confidence=confidence,
            observables=observables,
            mitre_techniques=mitre_techniques,
            recommended_actions=recommended_actions,
            tags=self._build_tags(
                severity=severity,
                priority=plan.priority,
                incident=incident,
            ),
        )

        self._tickets[ticket.ticket_id] = ticket

        self._mark_ticket_action_completed(
            plan=plan,
            ticket=ticket,
        )

        plan.update_status()

        return ticket

    def get_ticket(
        self,
        ticket_id: str,
    ) -> SOCTicket | None:
        """
        Retrieve a ticket by ticket ID.
        """

        return self._tickets.get(ticket_id)

    def get_ticket_by_incident(
        self,
        incident_id: str,
    ) -> SOCTicket | None:
        """
        Retrieve the newest ticket for an incident.
        """

        matching_tickets = [
            ticket
            for ticket in self._tickets.values()
            if ticket.incident_id == incident_id
        ]

        if not matching_tickets:
            return None

        return matching_tickets[-1]

    def list_tickets(
        self,
        status: str | None = None,
    ) -> list[SOCTicket]:
        """
        List tickets, optionally filtering by status.
        """

        tickets = list(self._tickets.values())

        if status is None:
            return tickets

        normalized_status = str(status).strip().lower()

        return [
            ticket
            for ticket in tickets
            if ticket.status == normalized_status
        ]

    def assign_ticket(
        self,
        ticket_id: str,
        analyst: str,
        team: str | None = None,
    ) -> SOCTicket:
        """
        Assign a ticket to an analyst.
        """

        ticket = self._require_ticket(ticket_id)
        ticket.assign(analyst=analyst, team=team)

        return ticket

    def update_ticket_status(
        self,
        ticket_id: str,
        status: str,
    ) -> SOCTicket:
        """
        Update a ticket's status.
        """

        ticket = self._require_ticket(ticket_id)
        ticket.update_status(status)

        return ticket

    def add_ticket_evidence(
        self,
        ticket_id: str,
        evidence: str,
    ) -> SOCTicket:
        """
        Add evidence to an existing ticket.
        """

        ticket = self._require_ticket(ticket_id)
        ticket.add_evidence(evidence)

        return ticket

    def _mark_ticket_action_completed(
        self,
        plan: ResponsePlan,
        ticket: SOCTicket,
    ) -> None:
        """
        Mark the first pending CREATE_TICKET action as simulated.
        """

        for action in plan.actions:
            if (
                action.action_type == ActionType.CREATE_TICKET
                and action.status
                in {
                    ActionStatus.PENDING,
                    ActionStatus.APPROVED,
                }
            ):
                action.mark_success(
                    {
                        "ticket_id": ticket.ticket_id,
                        "incident_id": ticket.incident_id,
                        "status": ticket.status,
                        "priority": ticket.priority.value,
                        "assigned_team": ticket.assigned_team,
                    }
                )

                return

    def _build_title(
        self,
        incident: dict[str, Any],
        severity: str,
    ) -> str:
        attack_type = self._normalize_text(
            incident.get("attack_type"),
            default="Security incident",
        )

        source_ip = self._normalize_text(
            incident.get("source_ip"),
        )

        if source_ip:
            return f"[{severity}] {attack_type} from {source_ip}"

        return f"[{severity}] {attack_type}"

    def _build_description(
        self,
        incident: dict[str, Any],
        plan: ResponsePlan,
        severity: str,
        risk_score: int,
        confidence: str,
    ) -> str:
        summary = self._normalize_text(
            incident.get("summary"),
            default="No incident summary was provided.",
        )

        action_names = [
            action.action_type.value
            for action in plan.actions
        ]

        actions_text = (
            ", ".join(action_names)
            if action_names
            else "No response actions generated"
        )

        return (
            f"{summary}\n\n"
            f"Incident ID: {plan.incident_id}\n"
            f"Severity: {severity}\n"
            f"Priority: {plan.priority.value}\n"
            f"Risk score: {risk_score}\n"
            f"Confidence: {confidence}\n"
            f"Response actions: {actions_text}\n"
            f"Plan status: {plan.status}"
        )

    def _build_tags(
        self,
        severity: str,
        priority: ResponsePriority,
        incident: dict[str, Any],
    ) -> list[str]:
        tags = [
            "agentic-soc",
            severity.lower(),
            priority.value.lower(),
        ]

        if incident.get("is_repeat_offender") is True:
            tags.append("repeat-offender")

        verdict = self._normalize_text(
            incident.get("verdict"),
        ).lower()

        if verdict:
            tags.append(verdict.replace(" ", "-"))

        return list(dict.fromkeys(tags))

    def _extract_risk_score(
        self,
        incident: dict[str, Any],
    ) -> int:
        candidates = [
            incident.get("combined_risk_score"),
            incident.get("risk_score"),
            self._nested_get(
                incident,
                "intelligence_summary",
                "risk_score",
            ),
            self._nested_get(
                incident,
                "threat_intelligence",
                "risk_score",
            ),
        ]

        for candidate in candidates:
            try:
                if candidate is not None:
                    return max(
                        0,
                        min(int(float(candidate)), 100),
                    )
            except (TypeError, ValueError):
                continue

        return 0

    def _extract_observables(
        self,
        incident: dict[str, Any],
    ) -> dict[str, list[str]]:
        return {
            "ips": self._flatten_strings(
                [
                    incident.get("source_ip"),
                    incident.get("ip_addresses"),
                    incident.get("ips"),
                    self._nested_get(
                        incident,
                        "indicators_of_compromise",
                        "ips",
                    ),
                ]
            ),
            "domains": self._flatten_strings(
                [
                    incident.get("domains"),
                    self._nested_get(
                        incident,
                        "indicators_of_compromise",
                        "domains",
                    ),
                ]
            ),
            "hashes": self._flatten_strings(
                [
                    incident.get("hashes"),
                    self._nested_get(
                        incident,
                        "indicators_of_compromise",
                        "hashes",
                    ),
                ]
            ),
            "hosts": self._flatten_strings(
                [
                    incident.get("hostname"),
                    incident.get("host"),
                    incident.get("hosts"),
                    incident.get("affected_hosts"),
                ]
            ),
            "users": self._flatten_strings(
                [
                    incident.get("username"),
                    incident.get("user"),
                    incident.get("users"),
                    incident.get("affected_users"),
                ]
            ),
        }

    def _extract_mitre_ids(
        self,
        incident: dict[str, Any],
    ) -> list[str]:
        raw_values = [
            incident.get("mitre_ids"),
            incident.get("mitre_techniques"),
            incident.get("mitre_attack"),
        ]

        result: list[str] = []

        for raw_value in raw_values:
            if not raw_value:
                continue

            if isinstance(raw_value, str):
                self._append_unique(
                    result,
                    raw_value.upper(),
                )

            elif isinstance(raw_value, dict):
                technique_id = (
                    raw_value.get("id")
                    or raw_value.get("technique_id")
                )

                if technique_id:
                    self._append_unique(
                        result,
                        str(technique_id).upper(),
                    )

            elif isinstance(raw_value, list):
                for item in raw_value:
                    if isinstance(item, str):
                        self._append_unique(
                            result,
                            item.upper(),
                        )

                    elif isinstance(item, dict):
                        technique_id = (
                            item.get("id")
                            or item.get("technique_id")
                        )

                        if technique_id:
                            self._append_unique(
                                result,
                                str(technique_id).upper(),
                            )

        return result

    def _require_ticket(
        self,
        ticket_id: str,
    ) -> SOCTicket:
        ticket = self.get_ticket(ticket_id)

        if ticket is None:
            raise KeyError(f"Ticket not found: {ticket_id}")

        return ticket

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
    def _append_unique(
        values: list[str],
        value: str,
    ) -> None:
        if value and value not in values:
            values.append(value)

    @staticmethod
    def _normalize_text(
        value: Any,
        default: str = "",
    ) -> str:
        if value is None:
            return default

        text = str(value).strip()

        return text if text else default