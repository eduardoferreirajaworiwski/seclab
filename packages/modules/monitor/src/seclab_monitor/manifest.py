from seclab.core.manifest import ModuleManifest

from seclab_monitor.cli import app as cli_app
from seclab_monitor.routes import router

manifest = ModuleManifest(
    name="monitor",
    version="0.1.0",
    router=router,
    cli=cli_app,
    models_module="seclab_monitor.models",
    needs_scope_guard=False,
    needs_approval=False,
    description=(
        "Real-time Certificate Transparency stream monitoring, scored through the phantom "
        "pipeline (absorbed from hydra-mapper)."
    ),
)
