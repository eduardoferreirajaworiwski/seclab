from seclab.core.manifest import ModuleManifest

from seclab_cve_watch.cli import app as cli_app
from seclab_cve_watch.routes import router

manifest = ModuleManifest(
    name="cve_watch",
    version="0.1.0",
    router=router,
    cli=cli_app,
    models_module="seclab_cve_watch.db",
    needs_scope_guard=False,
    needs_approval=False,
    description=(
        "CVE / CISA-KEV exploit tracker: ingests NVD and CISA KEV public feeds, tags CVEs "
        "against a configurable product/vendor watchlist, and produces a deterministic digest."
    ),
)
