from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TypeVar

from sqlalchemy.orm import Session

ModelT = TypeVar("ModelT")


def purge_older_than(
    db: Session, model: type[ModelT], *, days: int, timestamp_field: str = "created_at"
) -> int:
    """Deletes rows of `model` whose `timestamp_field` is older than `days`
    ago. Returns the number of rows deleted. Caller is responsible for
    invoking this explicitly (CLI command or manually) - nothing in
    seclab-core calls this automatically, since a personal lab's evidence
    trail should only be pruned by deliberate operator action, not a
    silent background job."""
    cutoff = datetime.now(UTC) - timedelta(days=days)
    column = getattr(model, timestamp_field)
    rows = db.query(model).filter(column < cutoff).all()
    for row in rows:
        db.delete(row)
    db.commit()
    return len(rows)
