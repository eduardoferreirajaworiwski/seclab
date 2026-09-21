from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from seclab.security.audit import AuditLogger
from seclab.security.models import ApprovalRequest, ApprovalStatus, role_rank


@dataclass
class ApprovalGateResult:
    allowed: bool
    message: str
    approval: ApprovalRequest | None = None
    commit_required: bool = False


class ApprovalWorkflowService:
    """Human-in-the-loop approval state machine, generalized from
    scopepilot/app/services/approval_workflow.py: the original was hardcoded
    to Hypothesis objects, here it gates any (subject_type, subject_id) pair
    so `recon` (hypothesis approval), `monitor` (active-capture approval) and
    future modules share one state machine and one audit trail. All the
    original safety properties are preserved verbatim: no two pending
    approvals for the same subject, self-approval is blocked, the approver's
    role must rank at or above required_role, and expiry is enforced lazily
    on read.
    """

    def __init__(self, db: Session, audit: AuditLogger) -> None:
        self.db = db
        self.audit = audit

    def request(
        self,
        *,
        subject_type: str,
        subject_id: str,
        required_role: str,
        requested_by: str,
        rationale: str,
        expires_at: datetime | None = None,
    ) -> ApprovalRequest:
        """Opens a new pending approval for (subject_type, subject_id),
        first expiring any stale pending one for the same subject. Raises
        409 if a still-pending approval already exists - one subject can
        only have one open approval decision in flight at a time."""
        self.expire_pending_for_subject(subject_type=subject_type, subject_id=subject_id)
        pending = self.db.scalar(
            select(ApprovalRequest).where(
                ApprovalRequest.subject_type == subject_type,
                ApprovalRequest.subject_id == subject_id,
                ApprovalRequest.status == ApprovalStatus.PENDING.value,
            )
        )
        if pending:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A pending approval already exists for this subject.",
            )

        approval = ApprovalRequest(
            subject_type=subject_type,
            subject_id=subject_id,
            required_role=required_role,
            requested_by=requested_by,
            request_rationale=rationale,
            status=ApprovalStatus.PENDING.value,
            expires_at=expires_at,
        )
        self.db.add(approval)
        self.db.flush()
        self.audit.log(
            event_type="approval_requested",
            entity_type=subject_type,
            entity_id=subject_id,
            actor=requested_by,
            decision="pending",
            reason="Sent for human validation.",
            metadata={
                "required_role": required_role,
                "request_rationale": rationale,
                "expires_at": expires_at.isoformat() if expires_at is not None else None,
            },
        )
        return approval

    def list_pending(self, *, subject_type: str | None = None) -> list[ApprovalRequest]:
        query = select(ApprovalRequest).where(
            ApprovalRequest.status == ApprovalStatus.PENDING.value
        )
        if subject_type:
            query = query.where(ApprovalRequest.subject_type == subject_type)
        query = query.order_by(desc(ApprovalRequest.created_at))

        active: list[ApprovalRequest] = []
        for approval in self.db.scalars(query):
            if self.expire_if_needed(approval):
                continue
            active.append(approval)
        return active

    def decide(
        self,
        approval: ApprovalRequest,
        *,
        approver: str,
        approver_role: str,
        status_value: str,
        rationale: str,
    ) -> ApprovalRequest:
        """Core approve/reject transition: expires the approval if its
        deadline already passed, blocks self-approval, and blocks an
        approver whose role ranks below required_role - each blocked case
        is itself audit-logged before raising, so a rejected/self decision
        attempt is not silently discarded."""
        if self.expire_if_needed(approval):
            self.db.commit()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Approval expired; request a new human review.",
            )

        if approval.status != ApprovalStatus.PENDING.value:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Approval has already been decided.",
            )

        if approval.requested_by == approver:
            reason = "Requester cannot decide their own approval."
            self._record_blocked(
                approval, actor=approver, reason=reason, metadata={"attempted_status": status_value}
            )
            self.db.commit()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)

        if role_rank(approver_role) < role_rank(approval.required_role):
            reason = "Approver's role does not meet the minimum required for this subject."
            self._record_blocked(
                approval,
                actor=approver,
                reason=reason,
                metadata={"approver_role": approver_role, "attempted_status": status_value},
            )
            self.db.commit()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)

        approval.approver = approver
        approval.approver_role = approver_role
        approval.status = status_value
        approval.decision_reason = rationale
        approval.decided_at = datetime.now(UTC)

        decision = "approved" if status_value == ApprovalStatus.APPROVED.value else "rejected"
        self.audit.log(
            event_type="approval_decided",
            entity_type=approval.subject_type,
            entity_id=approval.subject_id,
            actor=approver,
            decision=decision,
            reason=rationale,
            metadata={"approver_role": approver_role, "approval_id": approval.id},
        )
        return approval

    def approve(
        self, approval: ApprovalRequest, *, approver: str, approver_role: str, rationale: str
    ) -> ApprovalRequest:
        return self.decide(
            approval,
            approver=approver,
            approver_role=approver_role,
            status_value=ApprovalStatus.APPROVED.value,
            rationale=rationale,
        )

    def reject(
        self, approval: ApprovalRequest, *, approver: str, approver_role: str, rationale: str
    ) -> ApprovalRequest:
        return self.decide(
            approval,
            approver=approver,
            approver_role=approver_role,
            status_value=ApprovalStatus.REJECTED.value,
            rationale=rationale,
        )

    def evaluate_execution_gate(self, *, subject_type: str, subject_id: str) -> ApprovalGateResult:
        """Checks whether execution may proceed for a subject: looks at
        only the most recent approval request for it and requires that
        request to be APPROVED (not pending, rejected, or expired, and not
        missing entirely). This is the single choke point every module's
        execution-queueing endpoint must call before doing anything
        irreversible."""
        latest = self.db.scalar(
            select(ApprovalRequest)
            .where(
                ApprovalRequest.subject_type == subject_type,
                ApprovalRequest.subject_id == subject_id,
            )
            .order_by(desc(ApprovalRequest.created_at))
        )
        if latest is None:
            return ApprovalGateResult(
                allowed=False,
                message="Blocked: no human approval has been recorded for this subject.",
            )

        commit_required = self.expire_if_needed(latest)
        if latest.status == ApprovalStatus.PENDING.value:
            return ApprovalGateResult(
                allowed=False,
                message="Blocked: approval request is still pending.",
                commit_required=commit_required,
            )
        if latest.status == ApprovalStatus.REJECTED.value:
            return ApprovalGateResult(
                allowed=False,
                message="Blocked: the latest human decision rejected this subject.",
                commit_required=commit_required,
            )
        if latest.status == ApprovalStatus.EXPIRED.value:
            return ApprovalGateResult(
                allowed=False,
                message="Blocked: the approval expired before execution.",
                commit_required=commit_required,
            )

        return ApprovalGateResult(
            allowed=True,
            message="Valid human approval found.",
            approval=latest,
            commit_required=commit_required,
        )

    def expire_pending_for_subject(self, *, subject_type: str, subject_id: str) -> None:
        pending = list(
            self.db.scalars(
                select(ApprovalRequest).where(
                    ApprovalRequest.subject_type == subject_type,
                    ApprovalRequest.subject_id == subject_id,
                    ApprovalRequest.status == ApprovalStatus.PENDING.value,
                )
            )
        )
        for approval in pending:
            self.expire_if_needed(approval)

    def expire_if_needed(self, approval: ApprovalRequest) -> bool:
        if approval.status != ApprovalStatus.PENDING.value:
            return False
        expires_at = self._normalize_datetime(approval.expires_at)
        if expires_at is None or expires_at > datetime.now(UTC):
            return False

        approval.status = ApprovalStatus.EXPIRED.value
        approval.decision_reason = "Expired before a human decision."
        approval.decided_at = datetime.now(UTC)

        self.audit.log(
            event_type="approval_expired",
            entity_type=approval.subject_type,
            entity_id=approval.subject_id,
            actor="system",
            decision="expired",
            reason="Expired before human decision.",
            metadata={"expires_at": expires_at.isoformat() if expires_at is not None else None},
        )
        return True

    def _record_blocked(
        self, approval: ApprovalRequest, *, actor: str, reason: str, metadata: dict
    ) -> None:
        self.audit.log(
            event_type="approval_decision_blocked",
            entity_type=approval.subject_type,
            entity_id=approval.subject_id,
            actor=actor,
            decision="blocked",
            reason=reason,
            metadata=metadata,
        )

    def _normalize_datetime(self, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
