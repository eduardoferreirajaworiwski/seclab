from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from seclab.core.config import get_settings


class Base(DeclarativeBase):
    pass


def _build_engine():
    settings = get_settings()
    if not settings.database_url.startswith("sqlite"):
        return create_engine(settings.database_url, future=True)

    connect_args = {"check_same_thread": False}
    is_memory = ":memory:" in settings.database_url or not settings.database_url.replace(
        "sqlite:///", "", 1
    ).strip()
    if is_memory:
        # A plain sqlite ":memory:" DB is per-connection: any pool that opens
        # more than one connection (e.g. a FastAPI TestClient dispatching to
        # a worker thread) would see an empty, disconnected database. Pin the
        # engine to a single shared connection so schema/data stay visible
        # across every checkout - this matters for tests and for the CLI's
        # short-lived in-memory runs, not just the on-disk default DB.
        return create_engine(
            settings.database_url, connect_args=connect_args, poolclass=StaticPool, future=True
        )
    return create_engine(settings.database_url, connect_args=connect_args, future=True)


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables currently registered against the shared Base.

    Callers (the gateway's lifespan, the CLI, or a module's own test setup)
    must import every module's `models` submodule *before* calling this, so
    that module's tables have registered themselves on Base.metadata. The
    gateway does this explicitly per ModuleManifest at startup - see
    apps/gateway/src/seclab_gateway/registry.py.
    """
    Base.metadata.create_all(bind=engine)
