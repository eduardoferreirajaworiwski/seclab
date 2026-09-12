from datetime import UTC, datetime, timedelta

from seclab.core.retention import purge_older_than
from seclab.security.models import EvidenceArtifact


def test_purge_older_than_deletes_rows_past_the_cutoff(db_session):
    import seclab.security.models  # noqa: F401
    from seclab.core.db import Base, engine

    Base.metadata.create_all(bind=engine)

    old = EvidenceArtifact(
        source_module="test", subject_type="x", subject_id="1", evidence_type="t",
        content="old", content_sha256="a" * 64,
        created_at=datetime.now(UTC) - timedelta(days=100),
    )
    fresh = EvidenceArtifact(
        source_module="test", subject_type="x", subject_id="2", evidence_type="t",
        content="fresh", content_sha256="b" * 64,
    )
    db_session.add_all([old, fresh])
    db_session.commit()

    deleted = purge_older_than(db_session, EvidenceArtifact, days=90)

    assert deleted == 1
    remaining = db_session.query(EvidenceArtifact).all()
    assert len(remaining) == 1
    assert remaining[0].content == "fresh"
