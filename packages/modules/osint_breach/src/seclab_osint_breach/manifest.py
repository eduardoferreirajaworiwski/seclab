from seclab.core.manifest import ModuleManifest

from seclab_osint_breach.cli import app as cli_app
from seclab_osint_breach.routes import router

manifest = ModuleManifest(
    name="osint_breach",
    version="0.1.0",
    router=router,
    cli=cli_app,
    models_module="seclab_osint_breach.db",
    needs_scope_guard=False,
    needs_approval=False,
    description=(
        "Breach/leak watcher: checks watched email/domain identifiers against Have I Been "
        "Pwned (live, API-key-gated) or an offline fixture set, producing a deterministic "
        "exposure report. Read-only OSINT lookups against a third-party metadata API - same "
        "risk class as phantom/threatlens/cve_watch."
    ),
)
