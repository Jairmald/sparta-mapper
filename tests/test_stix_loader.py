"""
Unit tests for the STIX extraction functions, using a small synthetic
bundle rather than the real SPARTA data (so tests run offline and fast).
These test the *shape* of the parsing logic; they don't validate it
against the real schema — that's what `stix_loader.py --inspect` is for.
"""

from sparta_mapper.ingest.stix_loader import (
    _extract_countermeasures,
    _extract_relationships,
    _extract_techniques,
)

SYNTHETIC_OBJECTS = [
    {
        "type": "attack-pattern",
        "id": "attack-pattern--0001",
        "name": "Compromise Boot Memory",
        "description": "Adversary modifies bootloader to achieve persistence.",
        "external_references": [{"external_id": "EX-0003"}],
        "kill_chain_phases": [{"phase_name": "execution"}],
    },
    {
        "type": "course-of-action",
        "id": "course-of-action--0001",
        "name": "Secure Boot / firmware signing",
        "description": "Cryptographically verify firmware before execution.",
        "external_references": [{"external_id": "CM-0012"}],
    },
    {
        "type": "relationship",
        "relationship_type": "mitigates",
        "source_ref": "course-of-action--0001",
        "target_ref": "attack-pattern--0001",
    },
]


def test_extract_techniques():
    techniques = _extract_techniques(SYNTHETIC_OBJECTS)
    assert len(techniques) == 1
    assert techniques[0]["external_id"] == "EX-0003"
    assert techniques[0]["tactics"] == "execution"


def test_extract_countermeasures():
    cms = _extract_countermeasures(SYNTHETIC_OBJECTS)
    assert len(cms) == 1
    assert cms[0]["external_id"] == "CM-0012"


def test_extract_relationships():
    rels = _extract_relationships(SYNTHETIC_OBJECTS)
    assert len(rels) == 1
    assert rels[0]["relationship_type"] == "mitigates"
    assert rels[0]["source_ref"] == "course-of-action--0001"
    assert rels[0]["target_ref"] == "attack-pattern--0001"
