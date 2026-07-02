"""
Minimal FastAPI wrapper around the mapping pipeline. This is the Week 5
piece, scaffolded early so the CLI and API share the exact same
classify.map_text() call — no logic duplicated between them.

Run with: uvicorn sparta_mapper.api.main:app --reload
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sparta_mapper.classify.classifier import map_text

app = FastAPI(title="sparta-mapper API", version="0.1.0")

# Loosened for local dev against a React dev server. Tighten before deploying.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class MapRequest(BaseModel):
    text: str
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
    countermeasures: list[CountermeasureOut] = []


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/map", response_model=MapResponse)
def map_endpoint(req: MapRequest):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="text must not be empty")

    result = map_text(req.text, k=req.k)

    if not result.matched:
        return MapResponse(
            matched=False, confidence=result.confidence, reasoning=result.reasoning
        )

    return MapResponse(
        matched=True,
        external_id=result.technique.external_id,
        name=result.technique.name,
        tactics=result.technique.tactics,
        confidence=result.confidence,
        reasoning=result.reasoning,
        countermeasures=[
            CountermeasureOut(external_id=cm.external_id, name=cm.name)
            for cm in result.countermeasures
        ],
    )
