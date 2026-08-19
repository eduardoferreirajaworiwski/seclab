from seclab.core.manifest import ModuleManifest

from seclab_phantom.cli import app as cli_app
from seclab_phantom.routes import router

manifest = ModuleManifest(
    name="phantom",
    version="0.1.0",
    router=router,
    cli=cli_app,
    models_module="seclab_phantom.db",
    needs_scope_guard=False,
    needs_approval=False,
    description=(
        "Lookalike/typosquat domain detection via Certificate Transparency and "
        "infrastructure enrichment."
    ),
)
