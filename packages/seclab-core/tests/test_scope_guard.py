from seclab.security.scope_guard import (
    ProgramPolicy,
    ProposedAction,
    ScopeGuardService,
)


def test_no_allowlist_means_nothing_in_scope():
    guard = ScopeGuardService()
    policy = ProgramPolicy()
    result = guard.validate_target_in_scope(policy, identifier="example.com", target_type="domain")
    assert result.in_scope is False
    assert result.code == "scope_guard.missing_allowlist"


def test_allowlisted_domain_is_in_scope():
    guard = ScopeGuardService()
    policy = ProgramPolicy(allowed_domains=["example.com"])
    result = guard.validate_target_in_scope(policy, identifier="example.com", target_type="domain")
    assert result.in_scope is True


def test_wildcard_allowlist_matches_subdomain():
    guard = ScopeGuardService()
    policy = ProgramPolicy(allowed_domains=["*.example.com"])
    result = guard.validate_target_in_scope(
        policy, identifier="app.example.com", target_type="domain"
    )
    assert result.in_scope is True


def test_denylist_overrides_allowlist():
    guard = ScopeGuardService()
    policy = ProgramPolicy(allowed_domains=["*.example.com"], denied_domains=["prod.example.com"])
    result = guard.validate_target_in_scope(
        policy, identifier="prod.example.com", target_type="domain"
    )
    assert result.in_scope is False
    assert result.code == "scope_guard.denied_domain"


def test_forbidden_technique_blocks_action():
    guard = ScopeGuardService()
    policy = ProgramPolicy(
        allowed_domains=["example.com"], forbidden_techniques=["payload_injection"]
    )
    action = ProposedAction(target_identifier="example.com", technique="payload_injection")
    result = guard.validate_action(policy, action=action)
    assert result.allowed is False
    assert result.blocked is True
    assert result.code == "scope_guard.forbidden_technique"


def test_sensitive_technique_requires_manual_approval():
    guard = ScopeGuardService()
    policy = ProgramPolicy(allowed_domains=["example.com"])
    action = ProposedAction(target_identifier="example.com", technique="active_scan")
    result = guard.validate_action(policy, action=action)
    assert result.allowed is True
    assert result.requires_manual_approval is True


def test_out_of_scope_target_is_rejected_even_with_safe_technique():
    guard = ScopeGuardService()
    policy = ProgramPolicy(allowed_domains=["example.com"])
    action = ProposedAction(target_identifier="not-example.com", technique="manual_verification")
    result = guard.validate_action(policy, action=action)
    assert result.allowed is False
    assert result.code == "scope_guard.out_of_scope"
