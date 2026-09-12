import typer

from seclab_cli.retention import app as retention_app
from seclab_cli.users import app as users_app

app = typer.Typer(help="seclab - personal security laboratory CLI.")
app.add_typer(users_app, name="users")
app.add_typer(retention_app, name="retention")

try:
    from seclab_phantom.cli import app as phantom_app

    app.add_typer(phantom_app, name="phantom")
except ImportError:
    pass

try:
    from seclab_recon.cli import app as recon_app

    app.add_typer(recon_app, name="recon")
except ImportError:
    pass

try:
    from seclab_monitor.cli import app as monitor_app

    app.add_typer(monitor_app, name="monitor")
except ImportError:
    pass

try:
    from seclab_threatlens.cli import app as threatlens_app

    app.add_typer(threatlens_app, name="threatlens")
except ImportError:
    pass

try:
    from seclab_cve_watch.cli import app as cve_watch_app

    app.add_typer(cve_watch_app, name="cve_watch")
except ImportError:
    pass


if __name__ == "__main__":
    app()
