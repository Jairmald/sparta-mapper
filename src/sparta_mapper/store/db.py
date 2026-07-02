"""Read-only accessors for the local SPARTA knowledge store built by
ingest/stix_loader.py. Keeping this separate from the loader means the
retrieval and classification layers don't need to know anything about
SQLite or the STIX schema."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DB_PATH = Path(
    os.environ.get(
        "SPARTA_DB_PATH",
        Path(__file__).resolve().parents[3] / "data" / "sparta.db",
    )
)


@dataclass
class Technique:
    stix_id: str
    external_id: str
    name: str
    description: str
    tactics: str


@dataclass
class Countermeasure:
    stix_id: str
    external_id: str
    name: str
    description: str


def _connect(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    if not db_path.exists():
        raise FileNotFoundError(
            f"No store found at {db_path}. Run "
            f"`python -m sparta_mapper.ingest.stix_loader` first."
        )
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def all_techniques(db_path: Path = DEFAULT_DB_PATH) -> list[Technique]:
    conn = _connect(db_path)
    rows = conn.execute("SELECT * FROM techniques").fetchall()
    conn.close()
    return [Technique(**dict(row)) for row in rows]


def countermeasures_for(
    technique_stix_id: str, db_path: Path = DEFAULT_DB_PATH
) -> list[Countermeasure]:
    conn = _connect(db_path)
    rows = conn.execute(
        """
        SELECT c.* FROM countermeasures c
        JOIN technique_countermeasures tc ON tc.countermeasure_stix_id = c.stix_id
        WHERE tc.technique_stix_id = ?
        """,
        (technique_stix_id,),
    ).fetchall()
    conn.close()
    return [Countermeasure(**dict(row)) for row in rows]


def technique_by_external_id(external_id: str, db_path: Path = DEFAULT_DB_PATH) -> Technique | None:
    conn = _connect(db_path)
    row = conn.execute(
        "SELECT * FROM techniques WHERE external_id = ?", (external_id,)
    ).fetchone()
    conn.close()
    return Technique(**dict(row)) if row else None
