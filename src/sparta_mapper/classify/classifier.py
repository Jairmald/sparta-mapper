"""
Takes the top-k retrieved candidate techniques plus the raw CVE/advisory
text and asks Claude to pick the best match (or none), with reasoning and
a confidence score. This is the actual "AI" step — retrieval narrows the
field, the LLM does the judgment call a human analyst would otherwise make.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from anthropic import Anthropic
from dotenv import load_dotenv

from sparta_mapper.retrieval.embed import top_k_candidates
from sparta_mapper.store.db import Technique, countermeasures_for

load_dotenv()

MODEL = "claude-sonnet-4-6"

SYSTEM_PROMPT = """\
You are a space-systems cybersecurity analyst mapping vulnerability
descriptions to the Aerospace Corporation's SPARTA TTP framework.

You will be given a CVE/advisory description and a shortlist of candidate
SPARTA techniques (already narrowed by semantic search). Pick the single
best-matching technique, or none if nothing genuinely fits.

Respond with ONLY a JSON object, no other text, in this exact shape:
{
  "matched": true | false,
  "external_id": "EX-0003" | null,
  "confidence": 0.0-1.0,
  "reasoning": "1-3 sentences explaining the match, citing specifics from the input text"
}

Be conservative. A wrong confident mapping is worse than an honest "no good match".
If the input text doesn't describe a space/spacecraft/ground-segment relevant
vulnerability at all, set matched to false.
"""


@dataclass
class MappingResult:
    matched: bool
    technique: Technique | None
    confidence: float
    reasoning: str
    countermeasures: list


def map_text(input_text: str, k: int = 5) -> MappingResult:
    candidates = top_k_candidates(input_text, k=k)

    candidate_block = "\n\n".join(
        f"[{t.external_id}] {t.name}\n{t.description[:500]}"
        for t, _score in candidates
    )

    client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
    response = client.messages.create(
        model=MODEL,
        max_tokens=500,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": (
                    f"CVE/advisory text:\n{input_text}\n\n"
                    f"Candidate SPARTA techniques:\n{candidate_block}"
                ),
            }
        ],
    )

    raw = response.content[0].text.strip()
    raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Model did not return valid JSON: {raw!r}") from e

    if not parsed.get("matched"):
        return MappingResult(
            matched=False,
            technique=None,
            confidence=float(parsed.get("confidence", 0.0)),
            reasoning=parsed.get("reasoning", ""),
            countermeasures=[],
        )

    matched_technique = next(
        (t for t, _ in candidates if t.external_id == parsed["external_id"]),
        None,
    )
    cms = countermeasures_for(matched_technique.stix_id) if matched_technique else []

    return MappingResult(
        matched=True,
        technique=matched_technique,
        confidence=float(parsed.get("confidence", 0.0)),
        reasoning=parsed.get("reasoning", ""),
        countermeasures=cms,
    )
