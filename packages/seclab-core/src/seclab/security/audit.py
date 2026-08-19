import logging
from typing import Any

from sqlalchemy.orm import Session

from seclab.security.models import AuditLog


class AuditLogger:
    """Append-only, fail-closed audit trail. Generalized from scopepilot's
    DecisionLoggerService (app/services/decision_log.py): entity_type is now
    free text so any module can log against its own domain
    (e.g. "recon.hypothesis", "sensor_chimera.hit", "monitor.match")."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.logger = logging.getLogger("seclab.audit")

    def log(
        self,
        *,
        event_type: str,
        entity_type: str,
        entity_id: str | int | None,
        actor: str,
        decision: str,
        reason: str,
        metadata: dict[str, Any] | None = None,
    ) -> AuditLog:
        payload = metadata or {}
        entry = AuditLog(
            event_type=event_type,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id is not None else None,
            actor=actor,
            decision=decision,
            reason=reason,
            metadata_json=payload,
        )
        self.db.add(entry)
        self.db.flush()

        self.logger.info(
            "decision_recorded",
            extra={
                "event_type": event_type,
                "entity_type": entity_type,
                "entity_id": entry.entity_id,
                "actor": actor,
                "decision": decision,
                "reason": reason,
                "metadata": payload,
            },
        )
        return entry
