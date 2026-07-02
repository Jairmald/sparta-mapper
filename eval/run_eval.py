"""
Runs eval_set.json through the real pipeline and reports accuracy. This is
what turns "I built an AI tool" into "I built an AI tool that's right 80%
of the time on a labeled test set" — run it, put the number in the README,
update it as the classifier improves.

Usage: python eval/run_eval.py
"""

import json
from pathlib import Path

from sparta_mapper.classify.classifier import map_text

EVAL_SET_PATH = Path(__file__).parent / "eval_set.json"


def run() -> None:
    data = json.loads(EVAL_SET_PATH.read_text())
    cases = [c for c in data["cases"] if c["expected_external_id"] not in ("TODO",)
              and not c["expected_external_id"].startswith("PLACEHOLDER")]

    if not cases:
        print(
            "No usable eval cases yet — eval_set.json still has placeholder "
            "expected_external_id values. Verify them against the live "
            "SPARTA matrix and fill in real CVE cases before running this."
        )
        return

    correct = 0
    for case in cases:
        result = map_text(case["input_text"])
        got = result.technique.external_id if result.matched else None
        ok = got == case["expected_external_id"]
        correct += ok
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {case['id']}: expected {case['expected_external_id']}, got {got}")

    accuracy = correct / len(cases)
    print(f"\nAccuracy: {correct}/{len(cases)} ({accuracy:.0%})")


if __name__ == "__main__":
    run()
