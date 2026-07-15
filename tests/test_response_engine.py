from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from response_engine import (
    ActionExecutor,
    ActionStatus,
    ActionType,
    ApprovalManager,
    ApprovalStatus,
    AuditLogger,
    ResponseAction,
    ResponsePlan,
    ResponsePlanner,
    ResponsePolicyEngine,
    ResponsePriority,
    SOCTicket,
    TicketManager,
)


class ResponseEngineTestBase(unittest.TestCase):
    """
    Shared incident and helper methods for v0.6.0 tests.
    """

    def setUp(self) -> None:
        self.critical_incident = {
            "summary": (
                "Confirmed malicious PowerShell and "
                "command-and-control activity."
            ),
            "attack_type": "PowerShell Command and Control",
            "severity": "CRITICAL",
            "combined_risk_score": 91,
            "confidence": "High",
            "verdict": "confirmed_malicious",
            "source_ip": "185.220.101.45",
            "hostname": "EMP1",
            "username": "compromised.user",
            "is_repeat_offender": True,
            "correlation_level": "CRITICAL",
            "mitre_ids": [
                "T1059.001",
                "T1105",
            ],
        }

        self.low_risk_incident = {
            "summary": "Low-risk observable detected.",
            "attack_type": "Unknown Activity",
            "severity": "LOW",
            "combined_risk_score": 20,
            "confidence": "High",
            "verdict": "unknown",
            "source_ip": "203.0.113.10",
            "is_repeat_offender": False,
            "correlation_level": "NONE",
            "mitre_ids": [],
        }

        self.trusted_incident = {
            "summary": "Trusted infrastructure observed.",
            "attack_type": "Benign Network Activity",
            "severity": "LOW",
            "combined_risk_score": 2,
            "confidence": "High",
            "verdict": "trusted",
            "source_ip": "8.8.8.8",
            "is_repeat_offender": False,
            "correlation_level": "NONE",
            "mitre_ids": [],
        }

    def build_critical_decision_and_plan(
        self,
    ) -> tuple:
        decision = ResponsePolicyEngine().evaluate(
            self.critical_incident
        )

        plan = ResponsePlanner().build_plan(
            incident_id="INC-TEST-0001",
            decision=decision,
            incident=self.critical_incident,
        )

        return decision, plan


class TestResponseModels(ResponseEngineTestBase):
    def test_response_action_defaults(self) -> None:
        action = ResponseAction(
            action_type=ActionType.BLOCK_IP,
            target="185.220.101.45",
            reason="Confirmed malicious IP.",
        )

        self.assertTrue(
            action.action_id.startswith("ACT-")
        )
        self.assertEqual(
            action.status,
            ActionStatus.PENDING,
        )
        self.assertTrue(action.requires_approval)
        self.assertTrue(action.simulation_mode)
        self.assertIsNone(action.executed_at)

    def test_response_action_mark_success_in_simulation(
        self,
    ) -> None:
        action = ResponseAction(
            action_type=ActionType.MONITOR,
            target="203.0.113.10",
            reason="Monitor observable.",
            requires_approval=False,
            simulation_mode=True,
        )

        action.mark_success(
            {"message": "Monitoring enabled."}
        )

        self.assertEqual(
            action.status,
            ActionStatus.SIMULATED,
        )
        self.assertEqual(
            action.result["message"],
            "Monitoring enabled.",
        )
        self.assertIsNotNone(action.executed_at)

    def test_response_action_mark_failed(self) -> None:
        action = ResponseAction(
            action_type=ActionType.MONITOR,
            target="203.0.113.10",
            reason="Monitor observable.",
        )

        action.mark_failed("Test execution failure.")

        self.assertEqual(
            action.status,
            ActionStatus.FAILED,
        )
        self.assertEqual(
            action.error,
            "Test execution failure.",
        )
        self.assertIsNotNone(action.executed_at)

    def test_completed_plan_accepts_rejected_actions(
        self,
    ) -> None:
        completed_action = ResponseAction(
            action_type=ActionType.MONITOR,
            target="203.0.113.10",
            reason="Monitor.",
            requires_approval=False,
        )
        completed_action.status = ActionStatus.SIMULATED

        rejected_action = ResponseAction(
            action_type=ActionType.BLOCK_IP,
            target="203.0.113.10",
            reason="Block.",
        )
        rejected_action.status = ActionStatus.REJECTED

        plan = ResponsePlan(
            incident_id="INC-TEST-0002",
            priority=ResponsePriority.P2,
            actions=[
                completed_action,
                rejected_action,
            ],
        )

        self.assertEqual(
            plan.update_status(),
            "completed",
        )
        self.assertIsNotNone(plan.completed_at)


class TestResponsePolicyEngine(ResponseEngineTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.engine = ResponsePolicyEngine()

    def test_critical_repeat_offender_is_p1(
        self,
    ) -> None:
        decision = self.engine.evaluate(
            self.critical_incident
        )

        self.assertEqual(
            decision.priority,
            ResponsePriority.P1,
        )
        self.assertEqual(decision.risk_score, 91)
        self.assertTrue(
            decision.requires_human_approval
        )
        self.assertFalse(
            decision.automatic_execution_allowed
        )

        self.assertIn(
            ActionType.BLOCK_IP,
            decision.recommended_actions,
        )
        self.assertIn(
            ActionType.ISOLATE_HOST,
            decision.recommended_actions,
        )
        self.assertIn(
            ActionType.CREATE_TICKET,
            decision.recommended_actions,
        )
        self.assertIn(
            ActionType.NOTIFY_SOC,
            decision.recommended_actions,
        )

    def test_low_risk_incident_is_monitored(
        self,
    ) -> None:
        decision = self.engine.evaluate(
            self.low_risk_incident
        )

        self.assertEqual(
            decision.priority,
            ResponsePriority.P4,
        )
        self.assertIn(
            ActionType.MONITOR,
            decision.recommended_actions,
        )
        self.assertFalse(
            decision.requires_human_approval
        )
        self.assertTrue(
            decision.automatic_execution_allowed
        )

    def test_trusted_verdict_produces_no_action(
        self,
    ) -> None:
        decision = self.engine.evaluate(
            self.trusted_incident
        )

        self.assertEqual(
            decision.priority,
            ResponsePriority.P4,
        )
        self.assertEqual(
            decision.recommended_actions,
            [ActionType.NO_ACTION],
        )
        self.assertFalse(
            decision.requires_human_approval
        )
        self.assertTrue(
            decision.automatic_execution_allowed
        )

    def test_low_confidence_removes_destructive_actions(
        self,
    ) -> None:
        incident = dict(self.critical_incident)
        incident["confidence"] = "Low"

        decision = self.engine.evaluate(incident)

        destructive_actions = {
            ActionType.BLOCK_IP,
            ActionType.ISOLATE_HOST,
            ActionType.DISABLE_USER,
            ActionType.RESET_PASSWORD,
        }

        self.assertFalse(
            destructive_actions.intersection(
                decision.recommended_actions
            )
        )

        self.assertIn(
            ActionType.MONITOR,
            decision.recommended_actions,
        )
        self.assertIn(
            ActionType.CREATE_TICKET,
            decision.recommended_actions,
        )
        self.assertFalse(
            decision.requires_human_approval
        )

    def test_risk_score_is_clamped(self) -> None:
        incident = dict(self.low_risk_incident)
        incident["combined_risk_score"] = 500

        decision = self.engine.evaluate(incident)

        self.assertEqual(decision.risk_score, 100)


class TestResponsePlanner(ResponseEngineTestBase):
    def test_plan_orders_actions_deterministically(
        self,
    ) -> None:
        _, plan = self.build_critical_decision_and_plan()

        action_names = [
            action.action_type
            for action in plan.actions
        ]

        expected_prefix = [
            ActionType.CREATE_TICKET,
            ActionType.NOTIFY_SOC,
            ActionType.COLLECT_FORENSICS,
            ActionType.BLOCK_IP,
            ActionType.ISOLATE_HOST,
        ]

        self.assertEqual(
            action_names[:5],
            expected_prefix,
        )

    def test_destructive_actions_require_approval(
        self,
    ) -> None:
        _, plan = self.build_critical_decision_and_plan()

        block_action = next(
            action
            for action in plan.actions
            if action.action_type == ActionType.BLOCK_IP
        )

        isolate_action = next(
            action
            for action in plan.actions
            if action.action_type
            == ActionType.ISOLATE_HOST
        )

        self.assertTrue(
            block_action.requires_approval
        )
        self.assertEqual(
            block_action.status,
            ActionStatus.AWAITING_APPROVAL,
        )

        self.assertTrue(
            isolate_action.requires_approval
        )
        self.assertEqual(
            isolate_action.status,
            ActionStatus.AWAITING_APPROVAL,
        )

        self.assertEqual(
            plan.status,
            "awaiting_approval",
        )

    def test_missing_host_does_not_create_isolation_action(
        self,
    ) -> None:
        incident = dict(self.critical_incident)
        incident.pop("hostname")

        decision = ResponsePolicyEngine().evaluate(
            incident
        )

        plan = ResponsePlanner().build_plan(
            incident_id="INC-TEST-0003",
            decision=decision,
            incident=incident,
        )

        isolate_actions = [
            action
            for action in plan.actions
            if action.action_type
            == ActionType.ISOLATE_HOST
        ]

        self.assertEqual(isolate_actions, [])


class TestTicketManager(ResponseEngineTestBase):
    def test_create_p1_ticket_assigns_soc_l2(
        self,
    ) -> None:
        _, plan = self.build_critical_decision_and_plan()

        manager = TicketManager()

        ticket = manager.create_ticket(
            incident=self.critical_incident,
            plan=plan,
        )

        self.assertIsInstance(ticket, SOCTicket)
        self.assertTrue(
            ticket.ticket_id.startswith("TKT-")
        )
        self.assertEqual(
            ticket.priority,
            ResponsePriority.P1,
        )
        self.assertEqual(
            ticket.assigned_team,
            "SOC_L2",
        )
        self.assertEqual(ticket.status, "open")
        self.assertEqual(ticket.risk_score, 91)

        ticket_action = next(
            action
            for action in plan.actions
            if action.action_type
            == ActionType.CREATE_TICKET
        )

        self.assertEqual(
            ticket_action.status,
            ActionStatus.SIMULATED,
        )
        self.assertEqual(
            ticket_action.result["ticket_id"],
            ticket.ticket_id,
        )

    def test_ticket_lifecycle(self) -> None:
        _, plan = self.build_critical_decision_and_plan()

        manager = TicketManager()

        ticket = manager.create_ticket(
            incident=self.critical_incident,
            plan=plan,
        )

        manager.assign_ticket(
            ticket_id=ticket.ticket_id,
            analyst="Subodh R. Sohani",
            team="SOC_L2",
        )

        self.assertEqual(
            ticket.assigned_to,
            "Subodh R. Sohani",
        )
        self.assertEqual(ticket.status, "assigned")

        manager.update_ticket_status(
            ticket_id=ticket.ticket_id,
            status="investigating",
        )

        self.assertEqual(
            ticket.status,
            "investigating",
        )

        manager.add_ticket_evidence(
            ticket_id=ticket.ticket_id,
            evidence="EVID-TEST-0001",
        )

        self.assertIn(
            "EVID-TEST-0001",
            ticket.evidence,
        )


class TestApprovalManager(ResponseEngineTestBase):
    def test_create_approval_requests_without_duplicates(
        self,
    ) -> None:
        _, plan = self.build_critical_decision_and_plan()
        manager = ApprovalManager()

        first_requests = manager.create_requests_for_plan(
            plan
        )
        second_requests = manager.create_requests_for_plan(
            plan
        )

        self.assertEqual(len(first_requests), 2)
        self.assertEqual(len(second_requests), 2)
        self.assertEqual(
            manager.export_state()["request_count"],
            2,
        )

    def test_approve_and_reject_actions(
        self,
    ) -> None:
        _, plan = self.build_critical_decision_and_plan()
        manager = ApprovalManager()

        requests = manager.create_requests_for_plan(plan)

        block_request = next(
            request
            for request in requests
            if request.requested_action
            == ActionType.BLOCK_IP
        )

        isolate_request = next(
            request
            for request in requests
            if request.requested_action
            == ActionType.ISOLATE_HOST
        )

        manager.approve(
            approval_id=block_request.approval_id,
            plan=plan,
            reviewed_by="Subodh R. Sohani",
            comment="Confirmed malicious IP.",
        )

        manager.reject(
            approval_id=isolate_request.approval_id,
            plan=plan,
            reviewed_by="Subodh R. Sohani",
            comment="Isolation deferred.",
        )

        self.assertEqual(
            block_request.status,
            ApprovalStatus.APPROVED,
        )
        self.assertEqual(
            isolate_request.status,
            ApprovalStatus.REJECTED,
        )

        block_action = next(
            action
            for action in plan.actions
            if action.action_id
            == block_request.action_id
        )

        isolate_action = next(
            action
            for action in plan.actions
            if action.action_id
            == isolate_request.action_id
        )

        self.assertEqual(
            block_action.status,
            ActionStatus.APPROVED,
        )
        self.assertEqual(
            isolate_action.status,
            ActionStatus.REJECTED,
        )

    def test_non_approval_action_is_rejected(
        self,
    ) -> None:
        manager = ApprovalManager()

        action = ResponseAction(
            action_type=ActionType.MONITOR,
            target="203.0.113.10",
            reason="Monitor IOC.",
            requires_approval=False,
        )

        with self.assertRaises(ValueError):
            manager.create_request(
                incident_id="INC-TEST-0004",
                action=action,
            )


class TestActionExecutor(ResponseEngineTestBase):
    def test_executor_runs_approved_and_safe_actions(
        self,
    ) -> None:
        _, plan = self.build_critical_decision_and_plan()

        approvals = ApprovalManager()
        requests = approvals.create_requests_for_plan(
            plan
        )

        for request in requests:
            if request.requested_action == ActionType.BLOCK_IP:
                approvals.approve(
                    approval_id=request.approval_id,
                    plan=plan,
                    reviewed_by="Subodh R. Sohani",
                    comment="Approved for simulation.",
                )
            else:
                approvals.reject(
                    approval_id=request.approval_id,
                    plan=plan,
                    reviewed_by="Subodh R. Sohani",
                    comment="Rejected for test.",
                )

        executor = ActionExecutor(
            simulation_mode=True
        )

        results = executor.execute_plan(
            plan=plan,
            actor="Subodh R. Sohani",
        )

        block_action = next(
            action
            for action in plan.actions
            if action.action_type == ActionType.BLOCK_IP
        )

        self.assertEqual(
            block_action.status,
            ActionStatus.SIMULATED,
        )
        self.assertEqual(
            block_action.result["provider"],
            "simulated_firewall",
        )
        self.assertEqual(
            block_action.result["actor"],
            "Subodh R. Sohani",
        )

        self.assertEqual(
            plan.status,
            "completed",
        )
        self.assertEqual(
            len(results),
            len(plan.actions),
        )

    def test_unapproved_action_does_not_execute(
        self,
    ) -> None:
        action = ResponseAction(
            action_type=ActionType.BLOCK_IP,
            target="185.220.101.45",
            reason="Block malicious IP.",
            requires_approval=True,
        )
        action.status = ActionStatus.AWAITING_APPROVAL

        result = ActionExecutor().execute_action(
            action=action,
            incident_id="INC-TEST-0005",
        )

        self.assertFalse(result["executed"])
        self.assertEqual(
            action.status,
            ActionStatus.AWAITING_APPROVAL,
        )


class TestAuditLogger(ResponseEngineTestBase):
    def test_audit_logger_persists_jsonl_events(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = (
                Path(temp_dir)
                / "audit"
                / "audit_log.jsonl"
            )

            audit = AuditLogger(log_path)

            event = audit.log_event(
                event_type="unit_test",
                action="test_action",
                actor="test_runner",
                status="success",
                incident_id="INC-TEST-0006",
            )

            self.assertEqual(
                audit.get_event_count(),
                1,
            )
            self.assertTrue(log_path.is_file())

            lines = log_path.read_text(
                encoding="utf-8"
            ).splitlines()

            self.assertEqual(len(lines), 1)

            persisted = json.loads(lines[0])

            self.assertEqual(
                persisted["event_id"],
                event.event_id,
            )
            self.assertEqual(
                persisted["incident_id"],
                "INC-TEST-0006",
            )

    def test_existing_audit_events_are_loaded(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "audit.jsonl"

            first_logger = AuditLogger(log_path)

            first_logger.log_event(
                event_type="unit_test",
                action="first_event",
                actor="test_runner",
                status="success",
            )

            second_logger = AuditLogger(log_path)

            self.assertEqual(
                second_logger.get_event_count(),
                1,
            )


class TestResponseEngineIntegration(ResponseEngineTestBase):
    def test_full_policy_to_audit_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_path = (
                Path(temp_dir)
                / "audit_log.jsonl"
            )

            policy_engine = ResponsePolicyEngine()
            planner = ResponsePlanner()
            ticket_manager = TicketManager()
            approval_manager = ApprovalManager()
            executor = ActionExecutor()
            audit = AuditLogger(audit_path)

            decision = policy_engine.evaluate(
                self.critical_incident
            )

            plan = planner.build_plan(
                incident_id="INC-INTEGRATION-0001",
                decision=decision,
                incident=self.critical_incident,
            )

            audit.log_plan_created(plan)

            requests = (
                approval_manager.create_requests_for_plan(
                    plan
                )
            )

            for request in requests:
                audit.log_approval_requested(request)

                if request.requested_action == ActionType.BLOCK_IP:
                    approval_manager.approve(
                        approval_id=request.approval_id,
                        plan=plan,
                        reviewed_by="Subodh R. Sohani",
                        comment="Approved for containment simulation.",
                    )
                else:
                    approval_manager.reject(
                        approval_id=request.approval_id,
                        plan=plan,
                        reviewed_by="Subodh R. Sohani",
                        comment="Rejected during integration test.",
                    )

                audit.log_approval_reviewed(request)

            ticket = ticket_manager.create_ticket(
                incident=self.critical_incident,
                plan=plan,
            )

            execution_results = executor.execute_plan(
                plan=plan,
                actor="Subodh R. Sohani",
            )

            for action in plan.actions:
                audit.log_action_execution(
                    action=action,
                    incident_id=plan.incident_id,
                    actor="Subodh R. Sohani",
                )

            audit.log_plan_completed(
                plan=plan,
                actor="Subodh R. Sohani",
            )

            self.assertEqual(
                decision.priority,
                ResponsePriority.P1,
            )
            self.assertEqual(
                ticket.assigned_team,
                "SOC_L2",
            )
            self.assertEqual(
                plan.status,
                "completed",
            )
            self.assertTrue(audit_path.is_file())
            self.assertGreater(
                audit.get_event_count(),
                0,
            )
            self.assertEqual(
                len(execution_results),
                len(plan.actions),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)