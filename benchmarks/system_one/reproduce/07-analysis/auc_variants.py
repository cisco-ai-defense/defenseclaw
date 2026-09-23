"""Quantify how much discriminative signal the shared `risk` variable discards.

The leaderboard ranks by `risk = 1 - P(disposition.allow)`, max over events. For the
Open-Jev family that variable absorbs the model's confirm mass, which is large on benign
traffic, so it can rank worse than chance even when the block channel is informative.
This computes a tie-corrected Mann-Whitney AUC for several ranking variables on the same
labels the scorer uses (A,B -> positive; D -> negative; C excluded), as a diagnostic.
"""
import argparse
import bisect
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, "$WORK/defenseclaw-system-one/benchmarks/scripts")
from benchmark_inventory_system_one_sources import read_jsonl, truth_grade  # noqa: E402


def auc(scores, labels):
    positives = [s for s, l in zip(scores, labels) if l]
    negatives = sorted(s for s, l in zip(scores, labels) if not l)
    if not positives or not negatives:
        return None
    wins = ties = 0
    for score in positives:
        wins += bisect.bisect_left(negatives, score)
        ties += bisect.bisect_right(negatives, score) - bisect.bisect_left(negatives, score)
    return (wins + 0.5 * ties) / (len(positives) * len(negatives))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--out")
    args = parser.parse_args()

    grades = {str(row["id"]): truth_grade(row) for row in read_jsonl(Path(args.cases))}
    agg = defaultdict(lambda: {"block": 0.0, "allow": 1.0, "confirm": 0.0})
    for row in read_jsonl(Path(args.predictions)):
        probs = row.get("probabilities") or {}
        entry = agg[str(row["case_id"])]
        entry["block"] = max(entry["block"], float(probs.get("disposition.block", 0.0)))
        entry["confirm"] = max(entry["confirm"], float(probs.get("disposition.confirm", 0.0)))
        entry["allow"] = min(entry["allow"], float(probs.get("disposition.allow", 1.0)))

    scored = [(grades.get(cid), entry) for cid, entry in agg.items()]
    scored = [(g, e) for g, e in scored if g in ("A", "B", "D")]
    labels = [g in ("A", "B") for g, _ in scored]

    variants = {
        "risk = 1 - P(allow)  [leaderboard variable]": lambda e: 1 - e["allow"],
        "P(block)": lambda e: e["block"],
        "P(block) + P(confirm)": lambda e: e["block"] + e["confirm"],
        "P(block) - P(confirm)": lambda e: e["block"] - e["confirm"],
    }
    result = {"model": args.label, "predictions": args.predictions,
              "positives_A_B": sum(labels), "negatives_D": len(labels) - sum(labels),
              "auc": {name: auc([fn(e) for _, e in scored], labels) for name, fn in variants.items()}}
    print(json.dumps(result, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
