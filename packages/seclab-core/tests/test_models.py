import pytest
from seclab.security.models import Role, role_rank


def test_role_rank_orders_security_lead_above_analyst():
    assert role_rank(Role.SECURITY_LEAD.value) > role_rank(Role.ANALYST.value)


def test_role_rank_rejects_unknown_role():
    # Used to return 0 for any unrecognized string, which let a hypothesis
    # creator set required_role to an arbitrary value and have every real
    # role's rank trivially satisfy the approval gate in
    # seclab.security.approval.ApprovalWorkflowService.decide.
    with pytest.raises(ValueError, match="unknown role"):
        role_rank("not-a-real-role")
