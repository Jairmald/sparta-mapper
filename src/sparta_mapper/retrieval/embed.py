"""
Embeds every SPARTA technique once (cached to disk) and does top-k cosine
similarity search against an input CVE/advisory description. Deliberately
not using a vector DB (Chroma/FAISS) yet — the technique count is small
enough (low hundreds) that a flat numpy array is faster to ship and easier
to debug. Swap in a real vector store if/when this stops being true.
"""

from __future__ import annotations

import os
import pickle
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer

from sparta_mapper.store.db import Technique, all_techniques

EMBED_MODEL_NAME = "all-MiniLM-L6-v2"  # small, fast, good enough for this scale
CACHE_PATH = Path(
    os.environ.get(
        "SPARTA_EMBED_CACHE",
        Path(__file__).resolve().parents[3] / "data" / "technique_embeddings.pkl",
    )
)

_model: SentenceTransformer | None = None


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        _model = SentenceTransformer(EMBED_MODEL_NAME)
    return _model


@dataclass
class EmbeddedTechniques:
    techniques: list[Technique]
    vectors: np.ndarray  # shape (n_techniques, embedding_dim)


def build_embeddings(force: bool = False) -> EmbeddedTechniques:
    if CACHE_PATH.exists() and not force:
        with open(CACHE_PATH, "rb") as f:
            return pickle.load(f)

    techniques = all_techniques()
    if not techniques:
        raise RuntimeError(
            "No techniques in the store — run the STIX loader first."
        )

    model = _get_model()
    texts = [f"{t.name}. {t.description}" for t in techniques]
    vectors = model.encode(texts, normalize_embeddings=True, show_progress_bar=True)

    result = EmbeddedTechniques(techniques=techniques, vectors=np.array(vectors))
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CACHE_PATH, "wb") as f:
        pickle.dump(result, f)
    return result


def top_k_candidates(query_text: str, k: int = 5, force_rebuild: bool = False) -> list[tuple[Technique, float]]:
    """Returns the k most similar techniques to query_text, with cosine
    similarity scores (higher = more similar, range -1 to 1)."""
    embedded = build_embeddings(force=force_rebuild)
    model = _get_model()

    query_vec = model.encode([query_text], normalize_embeddings=True)[0]
    scores = embedded.vectors @ query_vec  # cosine sim, since both are normalized

    top_indices = np.argsort(scores)[::-1][:k]
    return [(embedded.techniques[i], float(scores[i])) for i in top_indices]
