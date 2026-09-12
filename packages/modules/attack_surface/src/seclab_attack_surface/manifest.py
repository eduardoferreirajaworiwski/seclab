from seclab.core.manifest import ModuleManifest

from seclab_attack_surface.cli import app as cli_app
from seclab_attack_surface.routes import router

manifest = ModuleManifest(
    name="attack_surface",
    version="0.1.0",
    router=router,
    cli=cli_app,
    models_module="seclab_attack_surface.db",
    needs_scope_guard=True,
    needs_approval=False,
    description=(
        "Lightweight external attack-surface mapper: CT-log subdomain discovery, DNS "
        "resolution, and bounded/timed-out TCP-connect port probing on a small fixed port "
        "list, deterministically tagged for unexpected exposure. Requires an explicit "
        "ScopeGuardService allowlist check before any discovery or probing occurs - the "
        "only module that makes outbound TCP connections to arbitrary discovered hosts."
    ),
)
