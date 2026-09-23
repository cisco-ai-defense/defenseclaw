"""Parity gate: reproduce Open-Jev's own published held-out accuracy with our serving stack.

The s2 result for these adapters is poor and its ROC AUC is below 0.5, so before that is
reported it must be shown to be a genuine generalisation result rather than a serving bug.
This runs the model over its OWN published held-out test split
(ZefanCai/Open-Jev release-v2-redistributable) through the same loader, temperature and
scoring path used for s2, and compares against the model card's figures.

Model card, Open-Jev-9B, test split (10,532 rows of the original frozen mixture):
    hard accuracy 97.54%, expected accuracy 94.72%, NLL 0.130947, Brier 0.039113
The redistributable projection here is NOT byte-identical (it drops 1,700 wikispeedia
rows), so small deviations are expected; a collapse to chance would indicate a bug.
"""
import argparse
import gzip
import json
import math
import random
import sys
import time

sys.path.insert(0, "$WORK/sysone/Open-Jev")
from jev.metrics import softmax  # noqa: E402
from jev.model import DecisionModel  # noqa: E402


def load_rows(path, sample, seed):
    """Targets are reference distributions. A 'hard' row is a one-hot distribution;
    anything else is a soft-target row, which the card's hard accuracy excludes."""
    rows = []
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            target = row.get("target")
            if not isinstance(target, list) or not target:
                continue
            row["_hard"] = max(target) == 1.0
            rows.append(row)
    random.Random(seed).shuffle(rows)
    return rows[:sample] if sample else rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--test", required=True)
    parser.add_argument("--sample", type=int, default=600)
    parser.add_argument("--seed", type=int, default=741983)
    parser.add_argument("--device", default="cuda:0")
    parser.add_argument("--out")
    args = parser.parse_args()

    import torch
    temperature = json.loads(open(args.checkpoint + "/temperature.json").read())["temperature"]
    model = DecisionModel.load(args.checkpoint, device=args.device)
    rows = load_rows(args.test, args.sample, args.seed)

    hard = correct = 0
    all_rows = 0
    expected_mass = nll_total = brier_total = 0.0
    by_kind = {}
    started = time.perf_counter()
    for row in rows:
        record = {"id": row["id"], "state": row["state"], "kind": row["kind"],
                  "question": row["question"], "options": row["options"]}
        target = [float(value) for value in row["target"]]
        with torch.inference_mode():
            logits = model([record])[0].float().cpu().tolist()
        probs = softmax(logits, temperature)
        if len(probs) != len(target):
            continue
        chosen = max(range(len(probs)), key=probs.__getitem__)
        all_rows += 1
        # Expected accuracy: reference target mass at the chosen candidate, over ALL rows.
        expected_mass += target[chosen]
        nll_total += -sum(t * math.log(max(p, 1e-12)) for t, p in zip(target, probs))
        brier_total += sum((p - t) ** 2 for p, t in zip(probs, target))
        bucket = by_kind.setdefault(row["kind"], {"n": 0, "hard": 0, "correct": 0})
        bucket["n"] += 1
        if row["_hard"]:
            hard += 1
            bucket["hard"] += 1
            hit = target[chosen] == 1.0
            correct += hit
            bucket["correct"] += hit

    result = {
        "checkpoint": args.checkpoint, "temperature": temperature,
        "test_file": args.test, "rows_scored": all_rows, "hard_rows_scored": hard,
        "hard_accuracy": round(correct / hard, 6) if hard else None,
        "expected_accuracy": round(expected_mass / all_rows, 6) if all_rows else None,
        "nll": round(nll_total / all_rows, 6) if all_rows else None,
        "brier": round(brier_total / all_rows, 6) if all_rows else None,
        "by_kind": {k: {**v, "hard_accuracy": round(v["correct"] / v["hard"], 6) if v["hard"] else None}
                    for k, v in sorted(by_kind.items())},
        "seconds": round(time.perf_counter() - started, 1),
        "published_reference": {"split": "test", "hard_accuracy": 0.9754,
                                "expected_accuracy": 0.9472, "nll": 0.130947, "brier": 0.039113,
                                "note": "original frozen mixture, 10,532 rows; this file is the "
                                        "redistributable projection and is not byte-identical"},
    }
    print(json.dumps(result, indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, sort_keys=True)
            handle.write("\n")


if __name__ == "__main__":
    main()
