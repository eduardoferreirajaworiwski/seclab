from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, status
from seclab.security.approval import ApprovalWorkflowService
from seclab.security.audit import AuditLogger
from seclab.security.evidence import EvidenceStore
from seclab.security.models import ApprovalRequest, ApprovalStatus, User, role_rank
from seclab.security.scope_guard import ProgramPolicy, ScopeGuardService
from sqlalchemy.orm import Session

from seclab_recon.enums import ExecutionStatus, FindingStatus, HypothesisStatus
from seclab_recon.models import Execution, Finding, Hypothesis, Program, Target
from seclab_recon.schemas import ExecutionComplete, HypothesisCreate, ProgramCreate, TargetCreate

MODULE = "recon"


def _get_or_404(db: Session, model, entity_id: int, label: str):
    entity = db.get(model, entity_id)
    if entity is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{label} not found")
    return entity


class ProgramService:
    def __init__(self, db: Session, audit: AuditLogger) -> None:
        self.db = db
        self.audit = audit

    def create(self, payload: ProgramCreate, *, owner: str) -> Program:
        program = Program(
            name=payload.name,
            description=payload.description,
            owner=owner,
            scope_policy=payload.scope_policy.model_dump(mode="json"),
        )
        self.db.add(program)
        self.db.flush()
        self.audit.log(
            event_type="program_created",
            entity_type=f"{MODULE}.program",
            entity_id=program.id,
            actor=owner,
            decision="created",
            reason="New program registered.",
            metadata={"name": program.name},
        )
        self.db.commit()
        return program

    def list_all(self) -> list[Program]:
        return list(self.db.query(Program).order_by(Program.created_at.desc()))

    def get(self, program_id: int) -> Program:
        return _get_or_404(self.db, Program, program_id, "program")


class TargetService:
    """Every target is validated against the owning program's scope policy
    at creation time using seclab.security.scope_guard - a target created
    out-of-scope is persisted (for visibility/audit) but flagged in_scope=False
    and every downstream action refuses to treat it as authorized."""

    def __init__(self, db: Session, audit: AuditLogger) -> None:
        self.db = db
        self.audit = audit
        self.guard = ScopeGuardService()

    def create(self, program: Program, payload: TargetCreate, *, actor: str) -> Target:
        policy = ProgramPolicy.model_validate(program.scope_policy)
        result = self.guard.validate_target_in_scope(
            policy, identifier=payload.identifier, target_type=payload.target_type
        )
        target = Target(
            program_id=program.id,
            identifier=payload.identifier,
            target_type=payload.target_type,
            created_by=actor,
            in_scope=result.in_scope,
            scope_reason=result.message,
        )
        self.db.add(target)
        self.db.flush()
        self.audit.log(
            event_type="target_scope_checked",
            entity_type=f"{MODULE}.target",
            entity_id=target.id,
            actor=actor,
            decision="in_scope" if result.in_scope else "out_of_scope",
            reason=result.message,
            metadata={"code": result.code, "program_id": program.id},
        )
        self.db.commit()
        return target

    def list_for_program(self, program_id: int) -> list[Target]:
        return list(self.db.query(Target).filter(Target.program_id == program_id))

    def get(self, target_id: int) -> Target:
        return _get_or_404(self.db, Target, target_id, "target")


class HypothesisService:
    def __init__(self, db: Session, audit: AuditLogger) -> None:
        self.db = db
        self.audit = audit

    def create(self, target: Target, payload: HypothesisCreate, *, actor: str) -> Hypothesis:
        if not target.in_scope:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot create a hypothesis against an out-of-scope target.",
            )
        hypothesis = Hypothesis(
            program_id=target.program_id,
            target_id=target.id,
            title=payload.title,
            description=payload.description,
            confidence=payload.confidence,
            suggested_next_step=payload.suggested_next_step,
            required_role=payload.required_role.value,
            severity=payload.severity,
            created_by=actor,
            status=HypothesisStatus.DRAFT.value,
        )
        self.db.add(hypothesis)
        self.db.commit()
        return hypothesis

    def get(self, hypothesis_id: int) -> Hypothesis:
        return _get_or_404(self.db, Hypothesis, hypothesis_id, "hypothesis")

    def list_for_program(self, program_id: int) -> list[Hypothesis]:
        return list(
            self.db.query(Hypothesis)
            .filter(Hypothesis.program_id == program_id)
            .order_by(Hypothesis.created_at.desc())
        )


HYPOTHESIS_APPROVAL_SUBJECT_TYPE = f"{MODULE}.hypothesis"


class ApprovalService:
    """Thin adapter over seclab.security.approval.ApprovalWorkflowService:
    keeps the generic core state machine as the source of truth, and mirrors
    its decisions onto Hypothesis.status so the recon-specific workflow UI
    can read status directly off the hypothesis row."""

    def __init__(self, db: Session, audit: AuditLogger) -> None:
        self.db = db
        self.audit = audit
        self.workflow = ApprovalWorkflowService(db, audit)

    def request(
        self,
        hypothesis: Hypothesis,
        *,
        rationale: str,
        requested_by: str,
        expires_in_minutes: int | None,
    ):
        if hypothesis.status == HypothesisStatus.EXECUTED.value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Hypothesis already executed."
            )

        expires_at = (
            datetime.now(UTC) + timedelta(minutes=expires_in_minutes)
            if expires_in_minutes
            else None
        )
        approval = self.workflow.request(
            subject_type=HYPOTHESIS_APPROVAL_SUBJECT_TYPE,
            subject_id=str(hypothesis.id),
            required_role=hypothesis.required_role,
            requested_by=requested_by,
            rationale=rationale,
            expires_at=expires_at,
        )
        hypothesis.status = HypothesisStatus.PENDING_APPROVAL.value
        self.db.commit()
        return approval

    def list_pending(self):
        return self.workflow.list_pending(subject_type=HYPOTHESIS_APPROVAL_SUBJECT_TYPE)

    def decide(self, approval_id: int, *, approve: bool, rationale: str, approver: User):
        approval = _get_or_404(self.db, ApprovalRequest, approval_id, "approval")
        decide_fn = self.workflow.approve if approve else self.workflow.reject
        decided = decide_fn(
            approval, approver=approver.username, approver_role=approver.role, rationale=rationale
        )

        hypothesis = self.db.get(Hypothesis, int(decided.subject_id))
        if hypothesis is not None:
            hypothesis.status = (
                HypothesisStatus.APPROVED.value
                if decided.status == ApprovalStatus.APPROVED.value
                else HypothesisStatus.REJECTED.value
            )
        self.db.commit()
        return decided

    def evaluate_execution_gate(self, hypothesis: Hypothesis):
        return self.workflow.evaluate_execution_gate(
            subject_type=HYPOTHESIS_APPROVAL_SUBJECT_TYPE, subject_id=str(hypothesis.id)
        )


class ExecutionService:
    """Execution can only be queued once seclab.security.approval confirms a
    valid human approval exists for the hypothesis - mirrors scopepilot's
    evaluate_execution_gate, now backed by the generalized core workflow."""

    def __init__(self, db: Session, audit: AuditLogger, evidence: EvidenceStore) -> None:
        self.db = db
        self.audit = audit
        self.evidence = evidence
        self.approvals = ApprovalService(db, audit)

    def queue(self, hypothesis: Hypothesis, payload, *, requested_by: str) -> Execution:
        gate = self.approvals.evaluate_execution_gate(hypothesis)
        if not gate.allowed:
            self.audit.log(
                event_type="execution_blocked",
                entity_type=f"{MODULE}.hypothesis",
                entity_id=hypothesis.id,
                actor=requested_by,
                decision="blocked",
                reason=gate.message,
                metadata={},
            )
            self.db.commit()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=gate.message)

        execution = Execution(
            hypothesis_id=hypothesis.id,
            requested_by=requested_by,
            approved_by=gate.approval.approver if gate.approval else None,
            status=ExecutionStatus.QUEUED.value,
            action_plan=payload.action_plan,
            started_at=datetime.now(UTC),
        )
        self.db.add(execution)
        self.audit.log(
            event_type="execution_queued",
            entity_type=f"{MODULE}.execution",
            entity_id=None,
            actor=requested_by,
            decision="queued",
            reason="Execution authorized by a valid human approval.",
            metadata={"hypothesis_id": hypothesis.id},
        )
        self.db.commit()
        return execution

    def complete(self, execution: Execution, payload: ExecutionComplete, *, actor: str) -> Finding:
        if execution.status == ExecutionStatus.COMPLETED.value:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Execution has already been completed.",
            )

        hypothesis = _get_or_404(self.db, Hypothesis, execution.hypothesis_id, "hypothesis")

        execution.status = ExecutionStatus.COMPLETED.value
        execution.output_summary = payload.output_summary
        execution.completed_at = datetime.now(UTC)
        hypothesis.status = HypothesisStatus.EXECUTED.value

        finding = Finding(
            program_id=hypothesis.program_id,
            target_id=hypothesis.target_id,
            hypothesis_id=hypothesis.id,
            execution_id=execution.id,
            title=payload.finding_title,
            description=payload.finding_description,
            severity=payload.finding_severity,
            status=FindingStatus.NEW.value,
        )
        self.db.add(finding)
        self.db.flush()

        self.evidence.store(
            source_module=MODULE,
            subject_type="execution",
            subject_id=str(execution.id),
            evidence_type="execution_output",
            content=payload.output_summary,
        )
        self.audit.log(
            event_type="execution_completed",
            entity_type=f"{MODULE}.execution",
            entity_id=execution.id,
            actor=actor,
            decision="completed",
            reason="Execution completed and finding recorded.",
            metadata={"finding_id": finding.id},
        )
        self.db.commit()
        return finding

    def get(self, execution_id: int) -> Execution:
        return _get_or_404(self.db, Execution, execution_id, "execution")

    def list_for_hypothesis(self, hypothesis_id: int) -> list[Execution]:
        return list(
            self.db.query(Execution)
            .filter(Execution.hypothesis_id == hypothesis_id)
            .order_by(Execution.created_at.desc())
        )


class FindingService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_for_program(self, program_id: int) -> list[Finding]:
        return list(self.db.query(Finding).filter(Finding.program_id == program_id))


def can_approve(user: User, hypothesis: Hypothesis) -> bool:
    return role_rank(user.role) >= role_rank(hypothesis.required_role)
