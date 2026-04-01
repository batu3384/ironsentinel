from __future__ import annotations

import os
import sys

import typer
from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Footer, Header, Label, Static

cli = typer.Typer(help="__APP_TITLE__ Textual starter")


def is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty() and os.getenv("TERM") != "dumb"


def render_plain() -> None:
    typer.echo("__APP_TITLE__ console")
    typer.echo("1. Review the active workspace")
    typer.echo("2. Validate local dependencies")
    typer.echo("3. Start the first scan")


class ConsoleApp(App[None]):
    CSS = """
    Screen {
        padding: 1 2;
    }

    #title {
        color: cyan;
        text-style: bold;
        margin-bottom: 1;
    }

    .action {
        margin-top: 1;
    }

    #hint {
        color: grey50;
        margin-top: 1;
    }
    """

    BINDINGS = [("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Vertical():
            yield Static("__APP_TITLE__ operator cockpit", id="title")
            yield Label("Review the active workspace", classes="action")
            yield Label("Validate local dependencies", classes="action")
            yield Label("Start the first scan", classes="action")
            yield Static(
                "Primary action stays visible; plain fallback remains available outside interactive terminals.",
                id="hint",
            )
        yield Footer()


@cli.command()
def console(plain: bool = typer.Option(False, help="Force plain fallback output")) -> None:
    """Open the full-screen console."""
    if plain or os.getenv("NO_COLOR") or not is_interactive():
        render_plain()
        raise typer.Exit()

    app = ConsoleApp()
    app.run()


if __name__ == "__main__":
    cli()
