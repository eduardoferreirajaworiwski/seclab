import importlib

import typer

from seclab_cli.init import init_lab
from seclab_cli.retention import app as retention_app
from seclab_cli.users import app as users_app

app = typer.Typer(help="seclab - personal security laboratory CLI.")
app.add_typer(users_app, name="users")
app.add_typer(retention_app, name="retention")
app.command("init")(init_lab)

# Mirrors apps/gateway/src/seclab_gateway/registry.py's MODULE_MANIFEST_PATHS
# (kept as a separate list, not imported from the gateway package, because
# apps/cli must not depend on apps/gateway) - update both lists together
# when adding a module. osint_breach was deprecated - see the gateway
# registry's comment and packages/modules/osint_breach/DEPRECATED.md.
MODULE_CLI_APPS: list[tuple[str, str]] = [
    ("seclab_phantom.cli", "phantom"),
    ("seclab_recon.cli", "recon"),
    ("seclab_monitor.cli", "monitor"),
    ("seclab_threatlens.cli", "threatlens"),
    ("seclab_cve_watch.cli", "cve_watch"),
    ("seclab_attack_surface.cli", "attack_surface"),
    ("seclab_fusion.cli", "fusion"),
]

for module_path, command_name in MODULE_CLI_APPS:
    try:
        module = importlib.import_module(module_path)
    except ImportError:
        continue
    app.add_typer(module.app, name=command_name)


if __name__ == "__main__":
    app()
