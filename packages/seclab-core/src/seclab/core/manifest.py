from dataclasses import dataclass
from typing import Any


@dataclass
class ModuleManifest:
    """The contract every module exposes so the gateway and CLI can mount it
    without hardcoding per-module wiring (see apps/gateway and apps/cli).

    - `router`: a fastapi.APIRouter, mounted at /api/v1/<name>.
    - `cli`: an optional typer.Typer sub-app (kept as `Any` here so
      seclab-core doesn't need a hard dependency on typer).
    - `models_module`: dotted import path to the module's SQLAlchemy models
      submodule (e.g. "seclab_phantom.db"); the gateway/CLI import this
      before calling seclab.core.db.init_db() so the module's tables
      register against the shared Base.
    - `needs_scope_guard` / `needs_approval`: informational flags a module
      sets to advertise that its routes depend on seclab.security gates -
      useful for the dashboard/CLI to display capability, and for tests
      that assert every target-touching module actually declares this.
    """

    name: str
    version: str
    router: Any
    cli: Any | None = None
    models_module: str | None = None
    needs_scope_guard: bool = False
    needs_approval: bool = False
    description: str = ""
