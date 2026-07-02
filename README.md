# sparta-mapper

**An open-source tool that maps CVEs and vendor security advisories to the
Aerospace Corporation's [SPARTA](https://sparta.aerospace.org/) space-cyber
threat framework — automatically.**

> Independent community project. Not endorsed, sponsored, or supported by
> The Aerospace Corporation. SPARTA content is used under its published
> terms of use — see [Disclaimer](#disclaimer) before redistributing data.

## Why this exists

SPARTA gives the space industry a shared taxonomy for spacecraft attack
TTPs (the space-sector equivalent of MITRE ATT&CK), distributed as a
machine-readable STIX 2.1 bundle. What's missing is the layer CISA built
for ATT&CK with its "Decider" tool: something that takes a real-world CVE
or advisory and tells you *which SPARTA technique this actually is*,
with reasoning and relevant countermeasures.

`sparta-mapper` is that layer.

```
$ sparta-map --cve CVE-2023-XXXXX

Technique:    EX-0003 — Compromise Boot Memory
Tactic:       Execution
Confidence:   0.84
Reasoning:    Advisory describes persistent firmware modification via
              unauthenticated bootloader access, matching SPARTA EX-0003's
              described TTP for boot-stage compromise...
Countermeasures:
  - CM-0012  Secure Boot / firmware signing
  - CM-0031  Bootloader access authentication
```

## How it works

1. **Ingest** — pull the official SPARTA STIX bundle, parse it with the
   `stix2` library, normalize techniques/tactics/countermeasures into a
   local SQLite store. (`src/sparta_mapper/ingest/`)
2. **Retrieve** — embed every technique's description with
   `sentence-transformers`, run top-k similarity search against the input
   text. (`src/sparta_mapper/retrieval/`)
3. **Classify** — send the input + retrieved candidates to Claude for
   structured classification: technique ID, confidence, reasoning,
   cross-referenced countermeasures. (`src/sparta_mapper/classify/`)
4. **Serve** — CLI (`sparta-map`) and a FastAPI backend for the web UI.

## Status

🚧 Early scaffold. See [`eval/eval_set.json`](eval/eval_set.json) for the
hand-labeled test cases used to track mapping accuracy as this develops —
numbers will be reported here once the classifier is wired up.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add your ANTHROPIC_API_KEY

python -m sparta_mapper.ingest.stix_loader   # builds data/sparta.db
sparta-map --text "Unauthenticated telnet access to ground station..."
```

## Roadmap

- [x] Repo scaffold
- [ ] STIX ingestion + local store (week 1)
- [ ] Embedding retrieval (week 2)
- [ ] LLM classification + eval harness (week 3)
- [ ] CLI with NVD CVE lookup (week 4)
- [ ] FastAPI + web UI (week 5)
- [ ] Public release, eval numbers in README (week 6)

## License

MIT for this codebase. SPARTA content itself is governed by Aerospace
Corporation's own terms — read them at sparta.aerospace.org before
redistributing derived data, not just code.

## Disclaimer

This is an independent, unofficial tool built on top of publicly published
SPARTA data. It is not affiliated with, endorsed by, or reviewed by The
Aerospace Corporation. Mapping output is a starting point for analyst
judgment, not an authoritative classification.
