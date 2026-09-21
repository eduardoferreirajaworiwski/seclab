from fastapi import APIRouter, Depends
from seclab.core.config import get_settings
from seclab.core.db import get_db
from seclab.security.audit import AuditLogger
from seclab.security.auth import get_current_user
from seclab.security.evidence import EvidenceStore
from seclab.security.models import User
from sqlalchemy.orm import Session

from seclab_recon.ai_tactics import TacticsAdvisorService
from seclab_recon.schemas import (
    ApprovalDecisionRequest,
    ApprovalRead,
    ApprovalRequestCreate,
    ExecutionComplete,
    ExecutionCreate,
    ExecutionRead,
    FindingRead,
    HypothesisCreate,
    HypothesisRead,
    HypothesisSuggestions,
    ProgramCreate,
    ProgramRead,
    TargetCreate,
    TargetRead,
)
from seclab_recon.services import (
    ApprovalService,
    ExecutionService,
    FindingService,
    HypothesisService,
    ProgramService,
    TargetService,
)

router = APIRouter(tags=["recon"])


def get_audit(db: Session = Depends(get_db)) -> AuditLogger:
    return AuditLogger(db)


def get_evidence(db: Session = Depends(get_db)) -> EvidenceStore:
    return EvidenceStore(db)


@router.post("/programs", response_model=ProgramRead)
def create_program(
    payload: ProgramCreate,
    db: Session = Depends(get_db),
    audit: AuditLogger = Depends(get_audit),
    user: User = Depends(get_current_user),
) -> ProgramRead:
    program = ProgramService(db, audit).create(payload, owner=user.username)
    return ProgramRead.model_validate(program)


@router.get("/programs", response_model=list[ProgramRead])
def list_programs(db: Session = Depends(get_db)) -> list[ProgramRead]:
    programs = ProgramService(db, AuditLogger(db)).list_all()
    return [ProgramRead.model_validate(p) for p in programs]


@router.get("/programs/{program_id}", response_model=ProgramRead)
def get_program(program_id: int, db: Session = Depends(get_db)) -> ProgramRead:
    program = ProgramService(db, AuditLogger(db)).get(program_id)
    return ProgramRead.model_validate(program)


@router.post("/programs/{program_id}/targets", response_model=TargetRead)
def create_target(
    program_id: int,
    payload: TargetCreate,
    db: Session = Depends(get_db),
    audit: AuditLogger = Depends(get_audit),
    user: User = Depends(get_current_user),
) -> TargetRead:
    program_service = ProgramService(db, audit)
    program = program_service.get(program_id)
    target = TargetService(db, audit).create(program, payload, actor=user.username)
    return TargetRead.model_validate(target)


@router.get("/programs/{program_id}/targets", response_model=list[TargetRead])
def list_targets(program_id: int, db: Session = Depends(get_db)) -> list[TargetRead]:
    targets = TargetService(db, AuditLogger(db)).list_for_program(program_id)
    return [TargetRead.model_validate(t) for t in targets]


@router.post(
    "/targets/{target_id}/ai-suggest-hypotheses", response_model=HypothesisSuggestions
)
async def suggest_hypotheses(
    target_id: int,
    db: Session = Depends(get_db),
    audit: AuditLogger = Depends(get_audit),
    user: User = Depends(get_current_user),
) -> HypothesisSuggestions:
    """Suggests candidate hypotheses for a target (attack techniques worth
    investigating) using the shared AI provider (Gemini-first, OpenAI
    fallback), or a deterministic checklist if AI is disabled/unavailable.
    Read-only: never creates a Hypothesis itself - the analyst reviews each
    suggestion and submits the ones worth pursuing via the existing
    create_hypothesis endpoint, so the approval workflow stays untouched."""
    target = TargetService(db, audit).get(target_id)
    existing = HypothesisService(db, audit).list_for_program(target.program_id)
    settings = get_settings()
    service = TacticsAdvisorService(settings)
    suggestions = await service.suggest(
        target, existing=existing, offline_mode=settings.offline_mode
    )
    audit.log(
        event_type="ai_hypotheses_suggested",
        entity_type="recon.target",
        entity_id=target.id,
        actor=user.username,
        decision="suggested",
        reason=f"model_source={suggestions.model_source}",
        metadata={"count": len(suggestions.suggestions)},
    )
    db.commit()
    return suggestions


@router.post("/targets/{target_id}/hypotheses", response_model=HypothesisRead)
def create_hypothesis(
    target_id: int,
    payload: HypothesisCreate,
    db: Session = Depends(get_db),
    audit: AuditLogger = Depends(get_audit),
    user: User = Depends(get_current_user),
) -> HypothesisRead:
    target = TargetService(db, audit).get(target_id)
    hypothesis = HypothesisService(db, audit).create(target, payload, actor=user.username)
    return HypothesisRead.model_validate(hypothesis)


@router.get("/hypotheses/{hypothesis_id}", response_model=HypothesisRead)
def get_hypothesis(hypothesis_id: int, db: Session = Depends(get_db)) -> HypothesisRead:
    hypothesis = HypothesisService(db, AuditLogger(db)).get(hypothesis_id)
    return HypothesisRead.model_validate(hypothesis)


@router.get("/programs/{program_id}/hypotheses", response_model=list[HypothesisRead])
def list_hypotheses(program_id: int, db: Session = Depends(get_db)) -> list[HypothesisRead]:
    hypotheses = HypothesisService(db, AuditLogger(db)).list_for_program(program_id)
    return [HypothesisRead.model_validate(h) for h in hypotheses]


@router.get("/hypotheses/{hypothesis_id}/executions", response_model=list[ExecutionRead])
def list_hypothesis_executions(
    hypothesis_id: int, db: Session = Depends(get_db)
) -> list[ExecutionRead]:
    executions = ExecutionService(db, AuditLogger(db), EvidenceStore(db)).list_for_hypothesis(
        hypothesis_id
    )
    return [ExecutionRead.model_validate(e) for e in executions]


@router.post("/hypotheses/{hypothesis_id}/approval-requests", response_model=ApprovalRead)
def request_approval(
    hypothesis_id: int,
    payload: ApprovalRequestCreate,
    db: Session = Depends(get_db),
    audit: AuditLogger = Depends(get_audit),
    user: User = Depends(get_current_user),
) -> ApprovalRead:
    hypothesis = HypothesisService(db, audit).get(hypothesis_id)
    approval = ApprovalService(db, audit).request(
        hypothesis,
        rationale=payload.rationale,
        requested_by=user.username,
        expires_in_minutes=payload.expires_in_minutes,
    )
    return ApprovalRead.model_validate(approval)


@router.get("/approvals/pending", response_model=list[ApprovalRead])
def list_pending_approvals(db: Session = Depends(get_db)) -> list[ApprovalRead]:
    approvals = ApprovalService(db, AuditLogger(db)).list_pending()
    return [ApprovalRead.model_validate(a) for a in approvals]


@router.post("/approvals/{approval_id}/approve", response_model=ApprovalRead)
def approve(
    approval_id: int,
    payload: ApprovalDecisionRequest,
    db: Session = Depends(get_db),
    audit: AuditLogger = Depends(get_audit),
    user: User = Depends(get_current_user),
) -> ApprovalRead:
    decided = ApprovalService(db, audit).decide(
        approval_id, approve=True, rationale=payload.rationale, approver=user
    )
    return ApprovalRead.model_validate(decided)


@router.post("/approvals/{approval_id}/reject", response_model=ApprovalRead)
def reject(
    approval_id: int,
    payload: ApprovalDecisionRequest,
    db: Session = Depends(get_db),
    audit: AuditLogger = Depends(get_audit),
    user: User = Depends(get_current_user),
) -> ApprovalRead:
    decided = ApprovalService(db, audit).decide(
        approval_id, approve=False, rationale=payload.rationale, approver=user
    )
    return ApprovalRead.model_validate(decided)


@router.post("/hypotheses/{hypothesis_id}/executions", response_model=ExecutionRead)
def queue_execution(
    hypothesis_id: int,
    payload: ExecutionCreate,
    db: Session = Depends(get_db),
    audit: AuditLogger = Depends(get_audit),
    evidence: EvidenceStore = Depends(get_evidence),
    user: User = Depends(get_current_user),
) -> ExecutionRead:
    hypothesis = HypothesisService(db, audit).get(hypothesis_id)
    execution = ExecutionService(db, audit, evidence).queue(
        hypothesis, payload, requested_by=user.username
    )
    return ExecutionRead.model_validate(execution)


@router.post("/executions/{execution_id}/complete", response_model=FindingRead)
def complete_execution(
    execution_id: int,
    payload: ExecutionComplete,
    db: Session = Depends(get_db),
    audit: AuditLogger = Depends(get_audit),
    evidence: EvidenceStore = Depends(get_evidence),
    user: User = Depends(get_current_user),
) -> FindingRead:
    service = ExecutionService(db, audit, evidence)
    execution = service.get(execution_id)
    finding = service.complete(execution, payload, actor=user.username)
    return FindingRead.model_validate(finding)


@router.get("/programs/{program_id}/findings", response_model=list[FindingRead])
def list_findings(program_id: int, db: Session = Depends(get_db)) -> list[FindingRead]:
    findings = FindingService(db).list_for_program(program_id)
    return [FindingRead.model_validate(f) for f in findings]
