"""CLI: sparta-map --cve CVE-2023-XXXXX | --text "..." """

from __future__ import annotations

import os

import requests
import typer
from dotenv import load_dotenv

from sparta_mapper.classify.classifier import map_text

load_dotenv()

app = typer.Typer(add_completion=False)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _fetch_cve_description(cve_id: str) -> str:
    """Pull the description for a CVE from NVD's free public API."""
    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    resp = requests.get(
        NVD_API_URL, params={"cveId": cve_id}, headers=headers, timeout=15
    )
    resp.raise_for_status()
    data = resp.json()

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        raise typer.BadParameter(f"No NVD record found for {cve_id}")

    descriptions = vulnerabilities[0]["cve"]["descriptions"]
    english = next((d["value"] for d in descriptions if d["lang"] == "en"), None)
    return english or descriptions[0]["value"]


@app.command()
def map(
    cve: str = typer.Option(None, help="CVE ID to look up via NVD, e.g. CVE-2023-1234"),
    text: str = typer.Option(None, help="Raw advisory/vulnerability text to classify directly"),
    k: int = typer.Option(5, help="Number of candidate techniques to retrieve before classification"),
):
    """Map a CVE or raw advisory text to a SPARTA technique."""
    if not cve and not text:
        raise typer.BadParameter("Provide either --cve or --text")

    if cve:
        typer.echo(f"Fetching {cve} from NVD...")
        input_text = _fetch_cve_description(cve)
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
