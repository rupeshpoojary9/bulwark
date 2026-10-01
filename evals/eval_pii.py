"""Score the PIIValidator against a labeled dataset.

Run:  python -m evals.eval_pii
Prints precision / recall / F1 / false-positive-rate and a confusion matrix.

Unlike InjectionValidator and ToxicityValidator, PIIValidator's default
action is REDACT, not BLOCK, so `result.blocked` isn't the right signal here.
A text "has PII" for this eval if the Guard produced any finding at all,
redacted or not.
"""
from __future__ import annotations

import json
import pathlib

from bulwark import Guard, PIIValidator

DATASET = pathlib.Path(__file__).resolve().parents[1] / "datasets" / \
    "pii_labeled.jsonl"


def load(path: pathlib.Path) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def evaluate(rows: list[dict]) -> dict:
    guard = Guard([PIIValidator()])
    tp = fp = tn = fn = 0
    for row in rows:
        predicted = 1 if guard.check(row["text"]).findings else 0
        actual = row["label"]
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision,
            "recall": recall, "f1": f1, "fpr": fpr, "n": len(rows)}


def main() -> None:
    m = evaluate(load(DATASET))
    print(f"n={m['n']}  TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}")
    print(f"precision={m['precision']:.3f}  recall={m['recall']:.3f}  "
          f"f1={m['f1']:.3f}  false-positive-rate={m['fpr']:.3f}")


if __name__ == "__main__":
    main()
