from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _normalize_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    items = [value] if isinstance(value, str) else list(value)

    normalized: list[str] = []
    seen: set[str] = set()
    for item in items:
        cleaned = str(item).strip().lower()
        if not cleaned or cleaned in seen:
            continue
        normalized.append(cleaned)
        seen.add(cleaned)
    return normalized


class ProgramPolicyLimits(BaseModel):
    max_requests_per_minute: int = Field(default=30, ge=1)
    manual_approval_request_rate: int = Field(default=10, ge=1)
    max_targets_per_execution: int = Field(default=1, ge=1)
    manual_approval_techniques: list[str] = Field(
        default_factory=lambda: [
            "active_scan",
            "auth_testing",
            "content_discovery",
            "fuzzing",
            "manual_verification",
            "payload_injection",
        ]
    )

    @field_validator("manual_approval_techniques", mode="before")
    @classmethod
    def normalize_manual_approval_techniques(cls, value: Any) -> list[str]:
        return _normalize_str_list(value)

    @model_validator(mode="after")
    def validate_thresholds(self) -> "ProgramPolicyLimits":
        if self.manual_approval_request_rate > self.max_requests_per_minute:
            raise ValueError("manual_approval_request_rate cannot exceed max_requests_per_minute.")
        return self


class ProgramPolicy(BaseModel):
    model_config = ConfigDict(extra="ignore")

    allowed_domains: list[str] = Field(default_factory=list)
    denied_domains: list[str] = Field(default_factory=list)
    forbidden_techniques: list[str] = Field(default_factory=list)
    limits: ProgramPolicyLimits = Field(default_factory=ProgramPolicyLimits)
    notes: str | None = None

    @field_validator("allowed_domains", "denied_domains", "forbidden_techniques", mode="before")
    @classmethod
    def normalize_string_fields(cls, value: Any) -> list[str]:
        return _normalize_str_list(value)


class ProposedAction(BaseModel):
    target_identifier: str = Field(min_length=2, max_length=255)
    target_type: str = Field(default="domain", min_length=2, max_length=50)
    technique: str = Field(default="manual_verification", min_length=2, max_length=80)
    description: str = Field(default="", max_length=2000)
    request_rate_per_minute: int = Field(default=1, ge=1)
    target_count: int = Field(default=1, ge=1)
    state_changing: bool = False
    requires_authentication: bool = False

    @field_validator("technique")
    @classmethod
    def normalize_technique(cls, value: str) -> str:
        return value.strip().lower()


class TargetValidationResult(BaseModel):
    in_scope: bool
    code: str
    message: str
    normalized_target: str | None = None
    matched_rule: str | None = None


class ManualApprovalResult(BaseModel):
    requires_manual_approval: bool
    code: str
    message: str
    reasons: list[str] = Field(default_factory=list)


class ActionBlockResult(BaseModel):
    blocked: bool
    code: str
    message: str
    reasons: list[str] = Field(default_factory=list)


class ActionValidationResult(BaseModel):
    allowed: bool
    blocked: bool
    requires_manual_approval: bool
    code: str
    message: str
    reasons: list[str] = Field(default_factory=list)


class ScopeGuardService:
    """Fail-closed target/action gate. Every module that touches an external
    target routes through here: no allowlist means nothing is in scope,
    denylist always wins, and forbidden techniques / hard rate-and-target
    limits block outright rather than degrading silently. Ported near
    verbatim from scopepilot/app/services/scope_guard.py - it was already
    fully generic (no scopepilot-specific types), so it becomes shared core
    as-is, promoted from bug-bounty-only enforcement to a lab-wide gate used
    by OSINT modules too.
    """

    def validate_target_in_scope(
        self, policy: ProgramPolicy, *, identifier: str, target_type: str
    ) -> TargetValidationResult:
        normalized_target = self._normalize_target(identifier=identifier, target_type=target_type)
        if not normalized_target:
            return TargetValidationResult(
                in_scope=False,
                code="scope_guard.invalid_target",
                message="Could not extract a valid host from the given target.",
            )

        if not policy.allowed_domains:
            return TargetValidationResult(
                in_scope=False,
                code="scope_guard.missing_allowlist",
                message="Program has no explicit allowlist. No target can be treated as in-scope.",
                normalized_target=normalized_target,
            )

        denied_match = self._match_first(normalized_target, policy.denied_domains)
        if denied_match:
            return TargetValidationResult(
                in_scope=False,
                code="scope_guard.denied_domain",
                message=f"Target blocked by the program's denylist: '{denied_match}'.",
                normalized_target=normalized_target,
                matched_rule=denied_match,
            )

        allowed_match = self._match_first(normalized_target, policy.allowed_domains)
        if not allowed_match:
            return TargetValidationResult(
                in_scope=False,
                code="scope_guard.out_of_scope",
                message="Target outside the program's allowed scope. No allowlist rule matched.",
                normalized_target=normalized_target,
            )

        return TargetValidationResult(
            in_scope=True,
            code="scope_guard.in_scope",
            message=f"Target validated in-scope by rule '{allowed_match}'.",
            normalized_target=normalized_target,
            matched_rule=allowed_match,
        )

    def requires_manual_approval(
        self, policy: ProgramPolicy, *, action: ProposedAction
    ) -> ManualApprovalResult:
        reasons: list[str] = []

        if self._matches_technique(action, policy.limits.manual_approval_techniques):
            reasons.append(
                f"Technique '{action.technique}' classified as sensitive by program policy."
            )

        if action.request_rate_per_minute > policy.limits.manual_approval_request_rate:
            reasons.append("Request rate above the threshold that requires manual review.")

        if action.state_changing:
            reasons.append("Action may change target state.")

        if action.requires_authentication:
            reasons.append("Action interacts with an authenticated flow.")

        if reasons:
            return ManualApprovalResult(
                requires_manual_approval=True,
                code="scope_guard.manual_approval_required",
                message="The proposed action requires manual approval before execution.",
                reasons=reasons,
            )

        return ManualApprovalResult(
            requires_manual_approval=False,
            code="scope_guard.manual_approval_not_required",
            message="The action does not trigger additional manual-approval rules.",
        )

    def block_prohibited_action(
        self, policy: ProgramPolicy, *, action: ProposedAction
    ) -> ActionBlockResult:
        if self._matches_technique(action, policy.forbidden_techniques):
            return ActionBlockResult(
                blocked=True,
                code="scope_guard.forbidden_technique",
                message=f"Technique '{action.technique}' is forbidden for this program.",
                reasons=["Technique listed in forbidden_techniques."],
            )

        if action.request_rate_per_minute > policy.limits.max_requests_per_minute:
            return ActionBlockResult(
                blocked=True,
                code="scope_guard.request_rate_exceeded",
                message="Action exceeds the program's maximum requests-per-minute limit.",
                reasons=[
                    f"request_rate_per_minute={action.request_rate_per_minute} "
                    f"> max_requests_per_minute={policy.limits.max_requests_per_minute}"
                ],
            )

        if action.target_count > policy.limits.max_targets_per_execution:
            return ActionBlockResult(
                blocked=True,
                code="scope_guard.target_count_exceeded",
                message="Action touches more targets than the program policy allows.",
                reasons=[
                    f"target_count={action.target_count} "
                    f"> max_targets_per_execution={policy.limits.max_targets_per_execution}"
                ],
            )

        return ActionBlockResult(
            blocked=False,
            code="scope_guard.action_allowed",
            message="Action does not violate any forbidden rule or hard limit.",
        )

    def validate_action(
        self, policy: ProgramPolicy, *, action: ProposedAction
    ) -> ActionValidationResult:
        target_result = self.validate_target_in_scope(
            policy, identifier=action.target_identifier, target_type=action.target_type
        )
        if not target_result.in_scope:
            return ActionValidationResult(
                allowed=False,
                blocked=True,
                requires_manual_approval=False,
                code=target_result.code,
                message=target_result.message,
                reasons=[target_result.message],
            )

        block_result = self.block_prohibited_action(policy, action=action)
        if block_result.blocked:
            return ActionValidationResult(
                allowed=False,
                blocked=True,
                requires_manual_approval=False,
                code=block_result.code,
                message=block_result.message,
                reasons=block_result.reasons,
            )

        approval_result = self.requires_manual_approval(policy, action=action)
        if approval_result.requires_manual_approval:
            return ActionValidationResult(
                allowed=True,
                blocked=False,
                requires_manual_approval=True,
                code=approval_result.code,
                message=approval_result.message,
                reasons=approval_result.reasons,
            )

        return ActionValidationResult(
            allowed=True,
            blocked=False,
            requires_manual_approval=False,
            code="scope_guard.allowed",
            message="Target and action validated within program policy.",
        )

    def _normalize_target(self, *, identifier: str, target_type: str) -> str | None:
        candidate = identifier.strip()
        if not candidate:
            return None

        if target_type.lower() in {"domain", "hostname", "url"}:
            parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
            host = parsed.hostname or parsed.netloc or parsed.path
            normalized = host.strip().lower()
            return normalized or None

        return candidate.lower()

    def _match_first(self, host: str, patterns: list[str]) -> str | None:
        for pattern in patterns:
            if self._domain_matches(host, pattern):
                return pattern
        return None

    def _domain_matches(self, host: str, pattern: str) -> bool:
        normalized_pattern = pattern.strip().lower()
        if not normalized_pattern:
            return False
        if normalized_pattern.startswith("*."):
            suffix = normalized_pattern[2:]
            return host.endswith(f".{suffix}")
        return host == normalized_pattern

    def _matches_technique(self, action: ProposedAction, policy_terms: list[str]) -> bool:
        combined_text = f"{action.technique} {action.description}".lower()
        return any(term in combined_text for term in policy_terms)
