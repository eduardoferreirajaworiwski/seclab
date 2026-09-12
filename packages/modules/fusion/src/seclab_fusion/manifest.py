from seclab.core.manifest import ModuleManifest

from seclab_fusion.cli import app as cli_app
from seclab_fusion.routes import router

manifest = ModuleManifest(
    name="fusion",
    version="0.1.0",
    router=router,
    cli=cli_app,
    models_module=None,
    needs_scope_guard=False,
    needs_approval=False,
    description=(
        "Cross-module correlation feed: a thin read-only aggregator (no own persistence) that "
        "reads recent results from monitor, threatlens, and cve_watch and surfaces "
        "prioritized, scored, explainable correlated findings."
    ),
)
