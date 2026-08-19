from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field
from seclab.security.scope_guard import ProgramPolicy


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ProgramCreate(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    description: str = ""
    scope_policy: ProgramPolicy = Field(default_factory=ProgramPolicy)


class ProgramRead(ORMModel):
    id: int
    name: str
    description: str
    owner: str
    scope_policy: dict
    created_at: datetime


class TargetCreate(BaseModel):
    identifier: str = Field(min_length=2, max_length=255)
    target_type: str = Field(default="domain", min_length=2, max_length=50)


class TargetRead(ORMModel):
    id: int
    program_id: int
    identifier: str
    target_type: str
    created_by: str
    in_scope: bool
    scope_reason: str
    created_at: datetime


class HypothesisCreate(BaseModel):
    title: str = Field(min_length=3, max_length=180)
    description: str = Field(min_length=3)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    suggested_next_step: str = ""
    required_role: str = Field(default="analyst")
    severity: str = Field(default="medium")


class HypothesisRead(ORMModel):
    id: int
    program_id: int
    target_id: int
    title: str
    description: str
    confidence: float
    suggested_next_step: str
    required_role: str
    severity: str
    created_by: str
    status: str
    created_at: datetime
    updated_at: datetime


class ApprovalRequestCreate(BaseModel):
    rationale: str = Field(min_length=3)
    expires_in_minutes: int | None = Field(default=None, ge=1)


class ApprovalDecisionRequest(BaseModel):
    rationale: str = Field(min_length=3)


class ApprovalRead(ORMModel):
    id: int
    subject_type: str
    subject_id: str
    required_role: str
    requested_by: str
    request_rationale: str
    approver: str | None
    approver_role: str | None
    status: str
    decision_reason: str | None
    created_at: datetime
    expires_at: datetime | None
    decided_at: datetime | None


class ExecutionCreate(BaseModel):
    action_plan: str = Field(min_length=3)


class ExecutionRead(ORMModel):
    id: int
    hypothesis_id: int
    requested_by: str
    approved_by: str | None
    status: str
    action_plan: str
    output_summary: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class ExecutionComplete(BaseModel):
    output_summary: str = Field(min_length=1)
    finding_title: str = Field(min_length=3, max_length=180)
    finding_description: str = Field(min_length=3)
    finding_severity: str = Field(default="medium")


class FindingRead(ORMModel):
    id: int
    program_id: int
    target_id: int
    hypothesis_id: int
    execution_id: int
    title: str
    description: str
    severity: str
    status: str
    created_at: datetime
