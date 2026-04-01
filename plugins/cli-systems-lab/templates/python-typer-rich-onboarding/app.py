from __future__ import annotations

import os
import sys

import typer
from rich.console import Console
from rich.panel import Panel

app = typer.Typer(help="__APP_TITLE__ CLI starter")
console = Console(no_color=bool(os.getenv("NO_COLOR")))


def is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty() and os.getenv("TERM") != "dumb"


def render_plain() -> None:
    typer.echo("__APP_TITLE__ setup")
    typer.echo("1. Choose the active workspace")
    typer.echo("2. Validate the local toolchain")
    typer.echo("3. Save the default project profile")


@app.command()
def setup(plain: bool = typer.Option(False, help="Force plain fallback output")) -> None:
    """Run a compact onboarding flow."""
    if plain or not is_interactive():
        render_plain()
        raise typer.Exit()

    console.print(
        Panel.fit(
            "[bold cyan]__APP_TITLE__ onboarding[/bold cyan]\n"
            "Choose the workspace you want to activate first.",
            border_style="cyan",
        )
    )

    workspace = typer.prompt("Workspace", default="default")
    if not workspace.strip():
        raise typer.BadParameter("workspace cannot be empty")

    console.print("[yellow]Validating local toolchain...[/yellow]")
    console.print("[green]Saved profile for[/green] [bold]{workspace}[/bold]".format(workspace=workspace))
    console.print("[dim]Next command:[/dim] [bold]python app.py doctor[/bold]")


@app.command()
def doctor() -> None:
    """Show the first recovery path."""
    console.print("[bold cyan]__APP_TITLE__ doctor[/bold cyan]")
    console.print("- Python version")
    console.print("- Config path")
    console.print("- Workspace status")


if __name__ == "__main__":
    app()
