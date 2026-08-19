import pytest
from fastapi import HTTPException
from seclab.security.approval import ApprovalWorkflowService
from seclab.security.audit import AuditLogger
from seclab.security.models import ApprovalStatus, Role


@pytest.fixture()
def workflow(db_session):
    audit = AuditLogger(db_session)
    return ApprovalWorkflowService(db_session, audit)


def test_request_creates_pending_approval(workflow):
    approval = workflow.request(
        subject_type="recon.hypothesis",
        subject_id="1",
        required_role=Role.ANALYST.value,
        requested_by="alice",
        rationale="needs review",
    )
    assert approval.status == ApprovalStatus.PENDING.value


def test_duplicate_pending_request_is_rejected(workflow):
    workflow.request(
        subject_type="recon.hypothesis",
        subject_id="1",
        required_role=Role.ANALYST.value,
        requested_by="alice",
        rationale="r1",
    )
    with pytest.raises(HTTPException) as exc:
        workflow.request(
            subject_type="recon.hypothesis",
            subject_id="1",
            required_role=Role.ANALYST.value,
            requested_by="alice",
            rationale="r2",
        )
    assert exc.value.status_code == 409


def test_self_approval_is_blocked(workflow):
    approval = workflow.request(
        subject_type="recon.hypothesis",
        subject_id="1",
        required_role=Role.ANALYST.value,
        requested_by="alice",
        rationale="r1",
    )
    with pytest.raises(HTTPException) as exc:
        workflow.approve(
            approval, approver="alice", approver_role=Role.SECURITY_LEAD.value, rationale="ok"
        )
    assert exc.value.status_code == 403


def test_insufficient_role_is_blocked(workflow):
    approval = workflow.request(
        subject_type="recon.hypothesis",
        subject_id="1",
        required_role=Role.SECURITY_LEAD.value,
        requested_by="alice",
        rationale="r1",
    )
    with pytest.raises(HTTPException) as exc:
        workflow.approve(approval, approver="bob", approver_role=Role.ANALYST.value, rationale="ok")
    assert exc.value.status_code == 403


def test_sufficient_role_can_approve(workflow):
    approval = workflow.request(
        subject_type="recon.hypothesis",
        subject_id="1",
        required_role=Role.ANALYST.value,
        requested_by="alice",
        rationale="r1",
    )
    decided = workflow.approve(
        approval, approver="bob", approver_role=Role.SECURITY_LEAD.value, rationale="ok"
    )
    assert decided.status == ApprovalStatus.APPROVED.value


def test_execution_gate_blocks_without_approval(workflow):
    gate = workflow.evaluate_execution_gate(subject_type="recon.hypothesis", subject_id="unknown")
    assert gate.allowed is False


def test_execution_gate_allows_after_approval(workflow):
    approval = workflow.request(
        subject_type="recon.hypothesis",
        subject_id="1",
        required_role=Role.ANALYST.value,
        requested_by="alice",
        rationale="r1",
    )
    workflow.approve(
        approval, approver="bob", approver_role=Role.SECURITY_LEAD.value, rationale="ok"
    )
    gate = workflow.evaluate_execution_gate(subject_type="recon.hypothesis", subject_id="1")
    assert gate.allowed is True
