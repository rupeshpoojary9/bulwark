"""Score the full validator pipeline together: end-to-end and per-validator.

Run:  python -m evals.eval_combined

Each row in combined_labeled.jsonl carries an overall `label` (1 if the Guard
should flag the text at all) and an `expect` list naming which validator(s)
should be the ones to catch it. Reports end-to-end precision/recall/F1/FPR
the same way the single-validator evals do, plus, for every validator that
appears in at least one row's `expect` list, how often it actually fired when
expected.
"""
from __future__ import annotations

import json
import pathlib

from bulwark import (
    Guard,
    InjectionValidator,
    PIIValidator,
    SecretsValidator,
    ToxicityValidator,
)

DATASET = pathlib.Path(__file__).resolve().parents[1] / "datasets" / \
    "combined_labeled.jsonl"


def load(path: pathlib.Path) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def build_guard() -> Guard:
    return Guard([
        InjectionValidator(),
        ToxicityValidator(),
        SecretsValidator(),
        PIIValidator(),
    ])


def evaluate(rows: list[dict]) -> dict:
    guard = build_guard()
    tp = fp = tn = fn = 0
    expected_total: dict[str, int] = {}
    expected_hit: dict[str, int] = {}

    for row in rows:
        result = guard.check(row["text"])
        fired = {f.validator for f in result.findings}
        predicted = 1 if fired else 0
        actual = row["label"]

        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
        else:
            tn += 1

        for validator_name in row.get("expect", []):
            expected_total[validator_name] = expected_total.get(validator_name, 0) + 1
            if validator_name in fired:
                expected_hit[validator_name] = expected_hit.get(validator_name, 0) + 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    per_validator = {
        name: expected_hit.get(name, 0) / total
        for name, total in expected_total.items()
    }
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
        "n": len(rows), "per_validator": per_validator,
    }


def main() -> None:
    m = evaluate(load(DATASET))
    print("--- end-to-end (any validator should fire) ---")
    print(f"n={m['n']}  TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}")
    print(f"precision={m['precision']:.3f}  recall={m['recall']:.3f}  "
          f"f1={m['f1']:.3f}  false-positive-rate={m['fpr']:.3f}")
    print("\n--- per-validator catch rate (did the expected validator fire?) ---")
    for name, rate in sorted(m["per_validator"].items()):
        print(f"{name:<18} {rate:.3f}")


if __name__ == "__main__":
    main()
