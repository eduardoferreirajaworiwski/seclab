from enum import StrEnum


class HypothesisStatus(StrEnum):
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"


class ExecutionStatus(StrEnum):
    QUEUED = "queued"
    BLOCKED = "blocked"
    RUNNING = "running"
    COMPLETED = "completed"


class FindingStatus(StrEnum):
    NEW = "new"
    REPORTED = "reported"
    CLOSED = "closed"
