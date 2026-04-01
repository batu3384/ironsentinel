from __future__ import annotations

import os
import sys

import typer
from rich.console import Console
from rich.panel import Panel

app = typer.Typer(help="__APP_TITLE__ repair-flow starter")
console = Console(no_color=bool(os.getenv("NO_COLOR")))


def is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty() and os.getenv("TERM") != "dumb"


def plain_repair(check: str) -> None:
    typer.echo(f"Repair target: {check}")
    typer.echo("1. Inspect the current configuration")
    typer.echo("2. Restore the missing value")
    typer.echo("3. Re-run the validation command")


@app.command()
def doctor() -> None:
    """Show the shortest recovery path."""
    if not is_interactive():
        plain_repair("environment")
        raise typer.Exit()

    console.print(
        Panel.fit(
            "[bold yellow]Repair first[/bold yellow]\n"
            "The fastest recovery path is to validate config before retrying the main command.",
            border_style="yellow",
        )
    )
    console.print("[bold]Suggested checks[/bold]")
    console.print("- config path")
    console.print("- credential presence")
    console.print("- workspace status")


@app.command()
def repair(
    check: str = typer.Option("config", help="The subsystem to recover"),
    verbose: bool = typer.Option(False, help="Show raw diagnostics"),
) -> None:
    """Run a small repair-oriented flow."""
    if not is_interactive():
        plain_repair(check)
        raise typer.Exit(code=2)

    console.print(f"[bold yellow]Repair target:[/bold yellow] {check}")
    console.print("[green]Shortest action:[/green] restore the missing value and rerun validation.")
    if verbose:
        console.print("[dim]Raw diagnostic: simulated missing configuration key[/dim]")
    raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
