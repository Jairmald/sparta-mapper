"""CLI: sparta-map --cve CVE-2023-XXXXX | --text "..." """

from __future__ import annotations

import typer
from dotenv import load_dotenv

from sparta_mapper.classify.classifier import map_text
from sparta_mapper.nvd import CVENotFoundError, fetch_cve_description

load_dotenv()

app = typer.Typer(add_completion=False)


@app.command()
def map(
    cve: str = typer.Option(None, help="CVE ID to look up via NVD, e.g. CVE-2023-1234"),
    text: str = typer.Option(None, help="Raw advisory/vulnerability text to classify directly"),
    k: int = typer.Option(
        5, help="Number of candidate techniques to retrieve before classification"
    ),
):
    """Map a CVE or raw advisory text to a SPARTA technique."""
    if not cve and not text:
        raise typer.BadParameter("Provide either --cve or --text")

    if cve:
        typer.echo(f"Fetching {cve} from NVD...")
        try:
            input_text = fetch_cve_description(cve)
        except CVENotFoundError as e:
            raise typer.BadParameter(str(e)) from e
        typer.echo(f"Description: {input_text}\n")
    else:
        input_text = text

    result = map_text(input_text, k=k)

    if not result.matched:
        typer.secho("No confident SPARTA technique match found.", fg=typer.colors.YELLOW)
        typer.echo(f"Reasoning: {result.reasoning}")
        raise typer.Exit()

    t = result.technique
    typer.secho(f"Technique:    {t.external_id} — {t.name}", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"Tactic(s):    {t.tactics}")
    typer.echo(f"Confidence:   {result.confidence:.2f}")
    typer.echo(f"Reasoning:    {result.reasoning}")

    if result.countermeasures:
        typer.echo("\nCountermeasures:")
        for cm in result.countermeasures:
            typer.echo(f"  - {cm.external_id}  {cm.name}")
    else:
        typer.echo("\nNo countermeasures linked in the local store for this technique.")


if __name__ == "__main__":
    app()
