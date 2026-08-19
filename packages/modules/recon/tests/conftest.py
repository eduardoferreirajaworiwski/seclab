import os

os.environ.setdefault("SECLAB_DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECLAB_API_KEY_PEPPER", "test-pepper-not-for-prod")

import pytest
from seclab.core.db import Base, engine
from seclab.security.audit import AuditLogger
from seclab.security.keys import hash_api_key
from seclab.security.models import Role, User


@pytest.fixture()
def db_session():
    import seclab.security.models  # noqa: F401
    import seclab_recon.models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    from seclab.core.db import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def audit(db_session):
    return AuditLogger(db_session)


@pytest.fixture()
def make_user(db_session):
    from seclab.core.config import Settings

    settings = Settings(api_key_pepper="test-pepper-not-for-prod")

    def _make_user(*, username: str, role: str = Role.ANALYST.value) -> User:
        user = User(
            username=username, role=role, api_key_hash=hash_api_key(f"key-{username}", settings)
        )
        db_session.add(user)
        db_session.commit()
        return user

    return _make_user
