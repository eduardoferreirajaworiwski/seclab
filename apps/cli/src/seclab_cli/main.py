import typer

from seclab_cli.users import app as users_app

app = typer.Typer(help="seclab - personal security laboratory CLI.")
app.add_typer(users_app, name="users")

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


if __name__ == "__main__":
    app()
