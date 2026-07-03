"""
Fetch a CVE's description from NVD's free public API. Shared by the CLI
(--cve) and the FastAPI backend so both acquire CVE text the same way —
no duplicated lookup logic, mirroring how they share classify.map_text().
"""

from __future__ import annotations

import os

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVENotFoundError(Exception):
    """Raised when NVD has no record for the requested CVE ID."""


def fetch_cve_description(cve_id: str) -> str:
    """Return the English description for a CVE from NVD's public API.

    Uses NVD_API_KEY if set (higher rate limits); works without one.
    Raises CVENotFoundError if NVD has no matching record, or
    requests.RequestException on a network/HTTP failure.
    """
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
        raise CVENotFoundError(f"No NVD record found for {cve_id}")

    descriptions = vulnerabilities[0]["cve"]["descriptions"]
    english = next((d["value"] for d in descriptions if d["lang"] == "en"), None)
    return english or descriptions[0]["value"]
