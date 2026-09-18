from importlib import import_module

from fastapi import Depends, FastAPI
from seclab.core.manifest import ModuleManifest
from seclab.security.auth import get_current_user

# Explicit list, not entry-point autoloading: simpler and safer for a
# personal lab (no risk of an installed-but-untrusted package silently
# registering itself as a module). sensor_chimera is deliberately excluded
# - it is a separately deployable honeypot process, never mounted here.
# osint_breach was deprecated and unmounted (structurally redundant with
# the threatlens/cve_watch digest shape, narrowest personal-lab utility,
# and the only module requiring a paid third-party API key for its live
# path) - its code and tests remain under packages/modules/osint_breach/
# for at least one release cycle; see its DEPRECATED.md.
MODULE_MANIFEST_PATHS = [
    "seclab_phantom.manifest",
    "seclab_recon.manifest",
    "seclab_monitor.manifest",
    "seclab_threatlens.manifest",
    "seclab_cve_watch.manifest",
    "seclab_attack_surface.manifest",
    "seclab_fusion.manifest",
]


def load_manifests() -> list[ModuleManifest]:
    manifests = []
    for path in MODULE_MANIFEST_PATHS:
        module = import_module(path)
        manifests.append(module.manifest)
    return manifests


def register_models(manifests: list[ModuleManifest]) -> None:
    """Import each module's models submodule so its tables register against
    the shared seclab.core.db.Base before init_db() creates them."""
    for manifest in manifests:
        if manifest.models_module:
            import_module(manifest.models_module)


def mount_routers(app: FastAPI, manifests: list[ModuleManifest]) -> None:
    """Every mounted module requires an authenticated identity, enforced here
    rather than per-route: a module author cannot forget to add
    Depends(get_current_user) to a new endpoint, and this applies uniformly
    to phantom/monitor GETs that previously had no auth dependency at all.
    Only /api/v1/health (declared directly on `app`, not via a manifest)
    stays public."""
    for manifest in manifests:
        app.include_router(
            manifest.router,
            prefix=f"/api/v1/{manifest.name}",
            dependencies=[Depends(get_current_user)],
        )
