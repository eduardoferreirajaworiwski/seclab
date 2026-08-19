import hashlib
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from seclab.security.models import EvidenceArtifact


class EvidenceStore:
    """Generic chain-of-custody artifact store shared by every module.

    Consolidates two prior patterns into one auditable place:
    - scopepilot's Evidence table (app/db/models.py / app/services/evidence_store.py),
    - hydra-mapper's ad-hoc per-file `.hash` sidecars (forensics/collector.py),

    Any module (phantom scoring evidence, hydra/monitor screenshot+HTML
    captures, chimera sensor hits) stores content here with a computed
    content_sha256, and can look it up again by (source_module, subject).
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    def store(
        self,
        *,
        source_module: str,
        subject_type: str,
        subject_id: str,
        evidence_type: str,
        content: str,
        content_format: str = "text",
        artifact_uri: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceArtifact:
        content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        artifact = EvidenceArtifact(
            source_module=source_module,
            subject_type=subject_type,
            subject_id=subject_id,
            evidence_type=evidence_type,
            content=content,
            content_format=content_format,
            content_sha256=content_sha256,
            artifact_uri=artifact_uri,
            metadata_json=metadata or {},
        )
        self.db.add(artifact)
        self.db.flush()
        return artifact

    def store_bytes(
        self,
        *,
        source_module: str,
        subject_type: str,
        subject_id: str,
        evidence_type: str,
        raw: bytes,
        artifact_uri: str,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceArtifact:
        """For binary artifacts (screenshots, etc): the content itself lives
        on disk/object storage at artifact_uri, this row is the chain-of-
        custody hash pointer to it."""
        content_sha256 = hashlib.sha256(raw).hexdigest()
        artifact = EvidenceArtifact(
            source_module=source_module,
            subject_type=subject_type,
            subject_id=subject_id,
            evidence_type=evidence_type,
            content="",
            content_format="binary",
            content_sha256=content_sha256,
            artifact_uri=artifact_uri,
            metadata_json=metadata or {},
        )
        self.db.add(artifact)
        self.db.flush()
        return artifact

    def by_subject(
        self, *, source_module: str, subject_type: str, subject_id: str
    ) -> list[EvidenceArtifact]:
        return list(
            self.db.scalars(
                select(EvidenceArtifact).where(
                    EvidenceArtifact.source_module == source_module,
                    EvidenceArtifact.subject_type == subject_type,
                    EvidenceArtifact.subject_id == subject_id,
                )
            )
        )

    def by_module(self, *, source_module: str, limit: int = 100) -> list[EvidenceArtifact]:
        return list(
            self.db.scalars(
                select(EvidenceArtifact)
                .where(EvidenceArtifact.source_module == source_module)
                .order_by(EvidenceArtifact.created_at.desc())
                .limit(limit)
            )
        )
