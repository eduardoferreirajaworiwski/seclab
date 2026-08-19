import pytest
from fastapi import HTTPException
from seclab.security.scope_guard import ProgramPolicy
from seclab_recon.schemas import (
    ExecutionComplete,
    ExecutionCreate,
    HypothesisCreate,
    ProgramCreate,
    TargetCreate,
)
from seclab_recon.services import (
    ApprovalService,
    ExecutionService,
    FindingService,
    HypothesisService,
    ProgramService,
    TargetService,
)


def _make_program(db_session, audit, allowed=("example.com",)):
    payload = ProgramCreate(
        name="Acme Bounty", scope_policy=ProgramPolicy(allowed_domains=list(allowed))
    )
    return ProgramService(db_session, audit).create(payload, owner="owner")


def test_target_in_allowlist_is_marked_in_scope(db_session, audit):
    program = _make_program(db_session, audit)
    target = TargetService(db_session, audit).create(
        program, TargetCreate(identifier="example.com", target_type="domain"), actor="analyst"
    )
    assert target.in_scope is True


def test_target_outside_allowlist_is_marked_out_of_scope(db_session, audit):
    program = _make_program(db_session, audit)
    target = TargetService(db_session, audit).create(
        program, TargetCreate(identifier="not-example.com", target_type="domain"), actor="analyst"
    )
    assert target.in_scope is False


def test_hypothesis_cannot_be_created_against_out_of_scope_target(db_session, audit):
    program = _make_program(db_session, audit)
    target = TargetService(db_session, audit).create(
        program, TargetCreate(identifier="not-example.com", target_type="domain"), actor="analyst"
    )
    with pytest.raises(HTTPException) as exc:
        HypothesisService(db_session, audit).create(
            target,
            HypothesisCreate(title="finding hypothesis", description="description text"),
            actor="analyst",
        )
    assert exc.value.status_code == 403


def test_execution_blocked_without_approval(db_session, audit, evidence=None):
    from seclab.security.evidence import EvidenceStore

    program = _make_program(db_session, audit)
    target = TargetService(db_session, audit).create(
        program, TargetCreate(identifier="example.com", target_type="domain"), actor="analyst"
    )
    hypothesis = HypothesisService(db_session, audit).create(
        target,
        HypothesisCreate(title="finding hypothesis", description="description text"),
        actor="analyst",
    )
    service = ExecutionService(db_session, audit, EvidenceStore(db_session))
    with pytest.raises(HTTPException) as exc:
        service.queue(hypothesis, ExecutionCreate(action_plan="probe"), requested_by="analyst")
    assert exc.value.status_code == 403


def test_full_workflow_approval_to_finding(db_session, audit, make_user):
    from seclab.security.evidence import EvidenceStore

    requester = make_user(username="analyst1")
    approver = make_user(username="lead1", role="security_lead")

    program = _make_program(db_session, audit)
    target = TargetService(db_session, audit).create(
        program,
        TargetCreate(identifier="example.com", target_type="domain"),
        actor=requester.username,
    )
    hypothesis = HypothesisService(db_session, audit).create(
        target,
        HypothesisCreate(
            title="Reflected XSS", description="description text", required_role="security_lead"
        ),
        actor=requester.username,
    )

    approvals = ApprovalService(db_session, audit)
    approval = approvals.request(
        hypothesis,
        rationale="needs review",
        requested_by=requester.username,
        expires_in_minutes=None,
    )
    decided = approvals.decide(approval.id, approve=True, rationale="looks safe", approver=approver)
    assert decided.status == "approved"

    execution_service = ExecutionService(db_session, audit, EvidenceStore(db_session))
    execution = execution_service.queue(
        hypothesis, ExecutionCreate(action_plan="probe"), requested_by=requester.username
    )
    assert execution.status == "queued"

    finding = execution_service.complete(
        execution,
        ExecutionComplete(
            output_summary="confirmed reflected xss",
            finding_title="Reflected XSS on /search",
            finding_description="description text",
            finding_severity="high",
        ),
        actor=approver.username,
    )
    assert finding.severity == "high"

    findings = FindingService(db_session).list_for_program(program.id)
    assert len(findings) == 1


def test_self_approval_still_blocked_through_recon_service(db_session, audit, make_user):
    requester = make_user(username="analyst2")
    program = _make_program(db_session, audit)
    target = TargetService(db_session, audit).create(
        program,
        TargetCreate(identifier="example.com", target_type="domain"),
        actor=requester.username,
    )
    hypothesis = HypothesisService(db_session, audit).create(
        target,
        HypothesisCreate(title="finding hypothesis", description="description text"),
        actor=requester.username,
    )
    approvals = ApprovalService(db_session, audit)
    approval = approvals.request(
        hypothesis, rationale="r", requested_by=requester.username, expires_in_minutes=None
    )

    with pytest.raises(HTTPException) as exc:
        approvals.decide(approval.id, approve=True, rationale="self", approver=requester)
    assert exc.value.status_code == 403
