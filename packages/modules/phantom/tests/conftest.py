import os

os.environ.setdefault("SECLAB_DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECLAB_API_KEY_PEPPER", "test-pepper-not-for-prod")
os.environ.setdefault("SECLAB_OFFLINE_MODE", "true")

import pytest
from seclab.core.db import Base, engine


@pytest.fixture()
def db_session():
    import seclab_phantom.db  # noqa: F401  (register phantom tables)

    Base.metadata.create_all(bind=engine)
    from seclab.core.db import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        Base.metadata.drop_all(bind=engine)
