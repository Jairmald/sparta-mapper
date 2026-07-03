"""
Minimal FastAPI wrapper around the mapping pipeline. This is the Week 5
piece, scaffolded early so the CLI and API share the exact same
classify.map_text() call — no logic duplicated between them. CVE lookup
is likewise shared via sparta_mapper.nvd.fetch_cve_description().

Run with: uvicorn sparta_mapper.api.main:app --reload
"""

from __future__ import annotations

import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sparta_mapper.classify.classifier import map_text
from sparta_mapper.nvd import CVENotFoundError, fetch_cve_description

app = FastAPI(title="sparta-mapper API", version="0.1.0")

# Loosened for local dev against a React dev server. Tighten before deploying.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class MapRequest(BaseModel):
    text: str | None = None
    cve: str | None = None
    k: int = 5


class CountermeasureOut(BaseModel):
    external_id: str
    name: str


class MapResponse(BaseModel):
    matched: bool
    external_id: str | None = None
    name: str | None = None
    tactics: str | None = None
    confidence: float
    reasoning: str
    description: str | None = None  # the classified text, when it came from a CVE lookup
    countermeasures: list[CountermeasureOut] = []


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/map", response_model=MapResponse)
def map_endpoint(req: MapRequest):
    cve = (req.cve or "").strip()
    text = (req.text or "").strip()
    description = None

    if cve:
        try:
            input_text = fetch_cve_description(cve)
        except CVENotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        except requests.RequestException as e:
            raise HTTPException(status_code=502, detail=f"NVD lookup failed: {e}") from e
        description = input_text
    elif text:
        input_text = text
    else:
        raise HTTPException(status_code=400, detail="Provide either 'text' or 'cve'.")

    result = map_text(input_text, k=req.k)

    if not result.matched:
        return MapResponse(
            matched=False,
            confidence=result.confidence,
            reasoning=result.reasoning,
            description=description,
        )

    return MapResponse(
        matched=True,
        external_id=result.technique.external_id,
        name=result.technique.name,
        tactics=result.technique.tactics,
        confidence=result.confidence,
        reasoning=result.reasoning,
        description=description,
        countermeasures=[
            CountermeasureOut(external_id=cm.external_id, name=cm.name)
            for cm in result.countermeasures
        ],
    )
