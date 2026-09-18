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


# `engine`/`SessionLocal` used to be built at import time, which meant
# `import seclab.core.db` (transitively pulled in by nearly every CLI
# subcommand module, including ones that never touch the database) failed
# outright if Settings() couldn't be constructed yet - e.g. on a fresh
# checkout with no .env, `seclab --help` itself crashed with the
# SECLAB_API_KEY_PEPPER ValueError before any command ran. Building them
# lazily on first real use (via module __getattr__, PEP 562) means importing
# this module is always safe; only actually opening a DB session requires
# valid settings, at which point failing loudly is correct.
_engine = None
_session_local = None


def _get_engine():
    global _engine
    if _engine is None:
        _engine = _build_engine()
    return _engine


def _get_session_local():
    global _session_local
    if _session_local is None:
        _session_local = sessionmaker(
            bind=_get_engine(), autoflush=False, autocommit=False, future=True
        )
    return _session_local


def __getattr__(name: str):
    if name == "engine":
        return _get_engine()
    if name == "SessionLocal":
        return _get_session_local()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def get_db() -> Generator[Session, None, None]:
    db = _get_session_local()()
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
    Base.metadata.create_all(bind=_get_engine())
