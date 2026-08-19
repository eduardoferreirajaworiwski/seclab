from datetime import datetime

from pydantic import BaseModel, ConfigDict


class MonitorMatchRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    domain: str
    issuer: str
    matched_keyword: str
    technique: str
    score: int
    priority: str
    score_rationale: str
    capture_status: str
    created_at: datetime
