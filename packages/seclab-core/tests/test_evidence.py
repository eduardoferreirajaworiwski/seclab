import hashlib

from seclab.security.evidence import EvidenceStore


def test_store_computes_content_sha256(db_session):
    store = EvidenceStore(db_session)
    artifact = store.store(
        source_module="monitor",
        subject_type="domain",
        subject_id="evil.example.com",
        evidence_type="html_dump",
        content="<html>fake</html>",
    )
    expected = hashlib.sha256(b"<html>fake</html>").hexdigest()
    assert artifact.content_sha256 == expected


def test_by_subject_returns_only_matching_artifacts(db_session):
    store = EvidenceStore(db_session)
    store.store(
        source_module="monitor",
        subject_type="domain",
        subject_id="a.com",
        evidence_type="x",
        content="1",
    )
    store.store(
        source_module="monitor",
        subject_type="domain",
        subject_id="b.com",
        evidence_type="x",
        content="2",
    )
    results = store.by_subject(source_module="monitor", subject_type="domain", subject_id="a.com")
    assert len(results) == 1
    assert results[0].subject_id == "a.com"
