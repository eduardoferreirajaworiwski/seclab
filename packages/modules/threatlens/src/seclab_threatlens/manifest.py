from seclab.core.manifest import ModuleManifest

from seclab_threatlens.cli import app as cli_app
from seclab_threatlens.routes import router

manifest = ModuleManifest(
    name="threatlens",
    version="0.1.0",
    router=router,
    cli=cli_app,
    models_module="seclab_threatlens.db",
    needs_scope_guard=False,
    needs_approval=False,
    description=(
        "Weekly security-news ingestion, deterministic attack-vector tagging, "
        "and AI-assisted (Gemini) threat digest narrative."
    ),
)
