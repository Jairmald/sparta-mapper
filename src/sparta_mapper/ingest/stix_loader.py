"""
Pulls the official SPARTA STIX 2.1 bundle and normalizes it into local
SQLite tables (techniques, tactics, countermeasures, relationships).

SPARTA publishes its dataset at:
    https://sparta.aerospace.org/download/STIX?f=latest

IMPORTANT — read before trusting the parsing logic below:
SPARTA's STIX schema is modeled on the same conventions as MITRE ATT&CK
(attack-pattern for techniques, course-of-action for countermeasures,
relationship objects linking them, kill-chain-phases for tactics), but
the exact custom object/property names have not been verified against a
live pull in this environment (sparta.aerospace.org isn't reachable from
the sandbox this was scaffolded in). The first thing this script does is
fetch the real bundle and print a schema summary — run `--inspect` first,
compare the printed type names against the assumptions in
`_extract_techniques` / `_extract_countermeasures` below, and adjust the
field names if anything doesn't match. This is real Week 1 work, not
optional cleanup.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any

import requests

STIX_URL = "https://sparta.aerospace.org/download/STIX?f=latest"
DATA_DIR = Path(__file__).resolve().parents[3] / "data"
RAW_BUNDLE_PATH = DATA_DIR / "sparta_stix.json"
DB_PATH = Path(os.environ.get("SPARTA_DB_PATH", DATA_DIR / "sparta.db"))


def fetch_bundle(force: bool = False) -> dict[str, Any]:
    """Download the STIX bundle (or load the cached copy)."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if RAW_BUNDLE_PATH.exists() and not force:
        return json.loads(RAW_BUNDLE_PATH.read_text())

    resp = requests.get(STIX_URL, timeout=30)
    resp.raise_for_status()
    bundle = resp.json()
    RAW_BUNDLE_PATH.write_text(json.dumps(bundle, indent=2))
    return bundle


def inspect_schema(bundle: dict[str, Any]) -> None:
    """Print every distinct STIX object type + a sample object per type.

    Run this first. Compare against _extract_techniques/_extract_countermeasures
    before assuming the parser below is correct.
    """
    objects = bundle.get("objects", [])
    counts = Counter(obj.get("type", "UNKNOWN") for obj in objects)
    print(f"Total objects: {len(objects)}\n")
    print("Object type counts:")
    for type_name, count in counts.most_common():
        print(f"  {type_name:30s} {count}")

    print("\nSample object per type (first occurrence):")
    seen = set()
    for obj in objects:
        t = obj.get("type", "UNKNOWN")
        if t in seen:
            continue
        seen.add(t)
        print(f"\n--- {t} ---")
        print(json.dumps(obj, indent=2)[:800])


def _extract_techniques(objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Assumes ATT&CK-style 'attack-pattern' objects with an external_id
    like EX-0001 in external_references, and kill_chain_phases for tactic
    linkage. VERIFY against --inspect output before trusting this."""
    techniques = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        external_id = next(
            (
                ref.get("external_id")
                for ref in obj.get("external_references", [])
                if "external_id" in ref
            ),
            None,
        )
        tactics = [
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases", [])
        ]
        techniques.append(
            {
                "stix_id": obj["id"],
                "external_id": external_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "tactics": ",".join(t for t in tactics if t),
            }
        )
    return techniques


def _extract_countermeasures(objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Assumes 'course-of-action' objects. VERIFY against --inspect output."""
    countermeasures = []
    for obj in objects:
        if obj.get("type") != "course-of-action":
            continue
        external_id = next(
            (
                ref.get("external_id")
                for ref in obj.get("external_references", [])
                if "external_id" in ref
            ),
            None,
        )
        countermeasures.append(
            {
                "stix_id": obj["id"],
                "external_id": external_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
            }
        )
    return countermeasures


def _extract_relationships(objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """'mitigates' relationships link course-of-action -> attack-pattern."""
    rels = []
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rels.append(
            {
                "relationship_type": obj.get("relationship_type", ""),
                "source_ref": obj.get("source_ref", ""),
                "target_ref": obj.get("target_ref", ""),
            }
        )
    return rels


def build_store(bundle: dict[str, Any], db_path: Path = DB_PATH) -> None:
    objects = bundle.get("objects", [])
    techniques = _extract_techniques(objects)
    countermeasures = _extract_countermeasures(objects)
    relationships = _extract_relationships(objects)

    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.executescript(
        """
        DROP TABLE IF EXISTS techniques;
        DROP TABLE IF EXISTS countermeasures;
        DROP TABLE IF EXISTS technique_countermeasures;

        CREATE TABLE techniques (
            stix_id TEXT PRIMARY KEY,
            external_id TEXT,
            name TEXT,
            description TEXT,
            tactics TEXT
        );

        CREATE TABLE countermeasures (
            stix_id TEXT PRIMARY KEY,
            external_id TEXT,
            name TEXT,
            description TEXT
        );

        CREATE TABLE technique_countermeasures (
            technique_stix_id TEXT,
            countermeasure_stix_id TEXT,
            FOREIGN KEY (technique_stix_id) REFERENCES techniques(stix_id),
            FOREIGN KEY (countermeasure_stix_id) REFERENCES countermeasures(stix_id)
        );
        """
    )

    cur.executemany(
        "INSERT INTO techniques VALUES (:stix_id, :external_id, :name, :description, :tactics)",
        techniques,
    )
    cur.executemany(
        "INSERT INTO countermeasures VALUES (:stix_id, :external_id, :name, :description)",
        countermeasures,
    )

    technique_ids = {t["stix_id"] for t in techniques}
    cm_ids = {c["stix_id"] for c in countermeasures}
    # SPARTA does not use "mitigates"; countermeasure->technique links are
    # generic "related-to" edges (course-of-action source, attack-pattern
    # target). The direction filter below (cm source, technique target) is
    # what keeps this from over-linking, since "related-to" is also used for
    # technique<->subtechnique and countermeasure<->countermeasure edges.
    links = [
        (r["source_ref"], r["target_ref"])
        for r in relationships
        if r["relationship_type"] == "related-to"
        and r["source_ref"] in cm_ids
        and r["target_ref"] in technique_ids
    ]
    cur.executemany(
        "INSERT INTO technique_countermeasures VALUES (?, ?)",
        [(target, source) for source, target in links],
    )

    conn.commit()
    conn.close()

    print(f"Loaded {len(techniques)} techniques, {len(countermeasures)} "
          f"countermeasures, {len(links)} technique-countermeasure links "
          f"into {db_path}")
    if not techniques:
        print(
            "\nWARNING: zero techniques extracted. Run with --inspect and "
            "fix _extract_techniques — the schema assumption is wrong."
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--inspect", action="store_true", help="Print the STIX object schema and exit"
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Re-download the bundle instead of using the cache"
    )
    args = parser.parse_args()

    bundle = fetch_bundle(force=args.force)

    if args.inspect:
        inspect_schema(bundle)
        return

    build_store(bundle)


if __name__ == "__main__":
    main()
