from __future__ import annotations

from typing import Any

from .response_models import (
    ActionStatus,
    ApprovalRequest,
    ApprovalStatus,
    ResponseAction,
    ResponsePlan,
)


class ApprovalManager:
    """
    Manages human-in-the-loop approval for response actions.

    Responsibilities:
    - Create approval requests for approval-controlled actions
    - Approve or reject requests
    - Synchronize approval state with ResponseAction
    - Prevent duplicate requests
    - Track all approval requests in memory
    """

    def __init__(self) -> None:
        self._requests: dict[str, ApprovalRequest] = {}
        self._action_request_index: dict[str, str] = {}

    def create_requests_for_plan(
        self,
        plan: ResponsePlan,
    ) -> list[ApprovalRequest]:
        """
        Create approval requests for all actions in a plan that require
        analyst approval.

        Existing requests are reused rather than duplicated.
        """

        requests: list[ApprovalRequest] = []

        for action in plan.actions:
            if not action.requires_approval:
                continue

            if action.status in {
                ActionStatus.SKIPPED,
                ActionStatus.SUCCESS,
                ActionStatus.SIMULATED,
                ActionStatus.FAILED,
                ActionStatus.REJECTED,
            }:
                continue

            request = self.create_request(
                incident_id=plan.incident_id,
                action=action,
            )

            requests.append(request)

        plan.update_status()

        return requests

    def create_request(
        self,
        incident_id: str,
        action: ResponseAction,
    ) -> ApprovalRequest:
        """
        Create or return an approval request for one response action.
        """

        existing_request = self.get_request_by_action(action.action_id)

        if existing_request is not None:
            return existing_request

        if not action.requires_approval:
            raise ValueError(
                f"Action {action.action_id} does not require approval."
            )

        if action.status in {
            ActionStatus.SUCCESS,
            ActionStatus.SIMULATED,
            ActionStatus.FAILED,
            ActionStatus.SKIPPED,
            ActionStatus.REJECTED,
        }:
            raise ValueError(
                f"Cannot request approval for action in state "
                f"{action.status.value}."
            )

        request = ApprovalRequest(
            action_id=action.action_id,
            incident_id=incident_id,
            requested_action=action.action_type,
            target=action.target,
            reason=action.reason,
        )

        self._requests[request.approval_id] = request
        self._action_request_index[action.action_id] = request.approval_id

        action.status = ActionStatus.AWAITING_APPROVAL

        return request

    def approve(
        self,
        approval_id: str,
        plan: ResponsePlan,
        reviewed_by: str,
        comment: str | None = None,
    ) -> ApprovalRequest:
        """
        Approve an approval request and mark the related action approved.
        """

        request = self._require_request(approval_id)

        if request.status != ApprovalStatus.PENDING:
            raise ValueError(
                f"Approval request {approval_id} is already "
                f"{request.status.value}."
            )

        action = self._find_action(
            plan=plan,
            action_id=request.action_id,
        )

        if action.status != ActionStatus.AWAITING_APPROVAL:
            raise ValueError(
                f"Action {action.action_id} is not awaiting approval."
            )

        request.approve(
            reviewed_by=reviewed_by,
            comment=comment,
        )

        action.status = ActionStatus.APPROVED
        action.result["approval"] = {
            "approval_id": request.approval_id,
            "status": request.status.value,
            "reviewed_by": request.reviewed_by,
            "review_comment": request.review_comment,
            "reviewed_at": request.reviewed_at,
        }

        plan.update_status()

        return request

    def reject(
        self,
        approval_id: str,
        plan: ResponsePlan,
        reviewed_by: str,
        comment: str | None = None,
    ) -> ApprovalRequest:
        """
        Reject an approval request and mark the related action rejected.
        """

        request = self._require_request(approval_id)

        if request.status != ApprovalStatus.PENDING:
            raise ValueError(
                f"Approval request {approval_id} is already "
                f"{request.status.value}."
            )

        action = self._find_action(
            plan=plan,
            action_id=request.action_id,
        )

        if action.status != ActionStatus.AWAITING_APPROVAL:
            raise ValueError(
                f"Action {action.action_id} is not awaiting approval."
            )

        request.reject(
            reviewed_by=reviewed_by,
            comment=comment,
        )

        action.status = ActionStatus.REJECTED
        action.result["approval"] = {
            "approval_id": request.approval_id,
            "status": request.status.value,
            "reviewed_by": request.reviewed_by,
            "review_comment": request.review_comment,
            "reviewed_at": request.reviewed_at,
        }

        plan.update_status()

        return request

    def get_request(
        self,
        approval_id: str,
    ) -> ApprovalRequest | None:
        """
        Retrieve an approval request by approval ID.
        """

        return self._requests.get(approval_id)

    def get_request_by_action(
        self,
        action_id: str,
    ) -> ApprovalRequest | None:
        """
        Retrieve an approval request using its linked action ID.
        """

        approval_id = self._action_request_index.get(action_id)

        if approval_id is None:
            return None

        return self._requests.get(approval_id)

    def list_requests(
        self,
        status: ApprovalStatus | str | None = None,
    ) -> list[ApprovalRequest]:
        """
        List approval requests, optionally filtered by status.
        """

        requests = list(self._requests.values())

        if status is None:
            return requests

        normalized_status = self._normalize_approval_status(status)

        return [
            request
            for request in requests
            if request.status == normalized_status
        ]

    def get_pending_requests(
        self,
    ) -> list[ApprovalRequest]:
        """
        Return all requests currently waiting for analyst review.
        """

        return self.list_requests(ApprovalStatus.PENDING)

    def expire_request(
        self,
        approval_id: str,
        plan: ResponsePlan,
    ) -> ApprovalRequest:
        """
        Expire a pending approval request.

        The linked action is rejected to prevent later execution without
        a fresh approval.
        """

        request = self._require_request(approval_id)

        if request.status != ApprovalStatus.PENDING:
            raise ValueError(
                f"Only pending approval requests can expire. "
                f"Current status: {request.status.value}."
            )

        action = self._find_action(
            plan=plan,
            action_id=request.action_id,
        )

        request.status = ApprovalStatus.EXPIRED
        request.review_comment = "Approval request expired."
        action.status = ActionStatus.REJECTED

        action.result["approval"] = {
            "approval_id": request.approval_id,
            "status": request.status.value,
            "review_comment": request.review_comment,
        }

        plan.update_status()

        return request

    def _require_request(
        self,
        approval_id: str,
    ) -> ApprovalRequest:
        request = self.get_request(approval_id)

        if request is None:
            raise KeyError(
                f"Approval request not found: {approval_id}"
            )

        return request

    @staticmethod
    def _find_action(
        plan: ResponsePlan,
        action_id: str,
    ) -> ResponseAction:
        for action in plan.actions:
            if action.action_id == action_id:
                return action

        raise KeyError(
            f"Action {action_id} was not found in "
            f"plan {plan.plan_id}."
        )

    @staticmethod
    def _normalize_approval_status(
        status: ApprovalStatus | str,
    ) -> ApprovalStatus:
        if isinstance(status, ApprovalStatus):
            return status

        normalized = str(status).strip().lower()

        try:
            return ApprovalStatus(normalized)
        except ValueError as exc:
            raise ValueError(
                f"Unsupported approval status: {status}"
            ) from exc

    def export_state(self) -> dict[str, Any]:
        """
        Export all approval-manager state as serializable dictionaries.
        """

        return {
            "request_count": len(self._requests),
            "pending_count": len(self.get_pending_requests()),
            "requests": [
                request.to_dict()
                for request in self._requests.values()
            ],
        }