from seclab.core.manifest import ModuleManifest

from seclab_recon.cli import app as cli_app
from seclab_recon.routes import router

manifest = ModuleManifest(
    name="recon",
    version="0.1.0",
    router=router,
    cli=cli_app,
    models_module="seclab_recon.models",
    needs_scope_guard=True,
    needs_approval=True,
    description=(
        "Authorized bug-bounty workflow: program -> scope-checked target -> "
        "hypothesis -> human approval -> gated execution -> finding."
    ),
)
