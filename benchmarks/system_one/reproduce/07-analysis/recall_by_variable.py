#!/usr/bin/env python3
"""Recall at a capped block false-positive rate, for each of the published ranking variables.

`sysone-auc_variants.py` says how well each variable ORDERS a corpus.  An AUC is a whole-curve
property, so a variable can win it on the middle of the curve where no guardrail operates.  This
measures the same four variables at the low false-positive rates a guardrail actually runs at,
including the incumbent cascade's own operating point, so a row that quotes a better variable has
to say whether the advantage survives there.

The variables and the per-case aggregation are the ones sysone-auc_variants.py uses, and each
variable's AUC is recomputed here and checked against that script's own output for the same
prediction file: a drift between the two would mean the two figures on the page came from two
definitions, which is the thing this is here to prevent.
"""
from __future__ import annotations

import argparse
import bisect
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, "$WORK/defenseclaw-system-one/benchmarks/scripts")
from benchmark_inventory_system_one_sources import read_jsonl, truth_grade  # noqa: E402

# the caps the site's recall table already uses, plus the incumbent cascade's own block FPR, which
# is the only one of them that corresponds to a shipped operating point
CAPS = ["0.001", "0.00384502", "0.005", "0.01", "0.05"]

VARIANTS = {
    "risk = 1 - P(allow)  [leaderboard variable]": lambda e: 1 - e["allow"],
    "P(block)": lambda e: e["block"],
    "P(block) + P(confirm)": lambda e: e["block"] + e["confirm"],
    "P(block) - P(confirm)": lambda e: e["block"] - e["confirm"],
}


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


def at_cap(scores, labels, cap):
    """The published rule, from secjudge/code/recall_at_fpr.py.

    Enumerate every achievable operating point of `score >= threshold`, including the no-flag
    sentinel, then take the highest recall inside the cap and, among ties on recall, the first
    point seen -- which is the tightest threshold and so the fewest false positives.
    """
    pairs = sorted(zip(scores, labels), key=lambda p: -p[0])
    npos = sum(labels)
    nneg = len(labels) - npos
    pts = [{"threshold": None, "tp": 0, "fp": 0, "fpr": 0.0, "tpr": 0.0}]
    tp = fp = 0
    i = 0
    while i < len(pairs):
        score = pairs[i][0]
        while i < len(pairs) and pairs[i][0] == score:
            if pairs[i][1]:
                tp += 1
            else:
                fp += 1
            i += 1
        pts.append({"threshold": score, "tp": tp, "fp": fp,
                    "fpr": fp / nneg, "tpr": tp / npos})
    best = None
    for p in pts:
        if p["fpr"] <= cap and (best is None or p["tpr"] > best["tpr"]):
            best = p
    return {"threshold": None if best["threshold"] is None else round(best["threshold"], 8),
            "recall": round(best["tpr"], 6), "achieved_fpr": round(best["fpr"], 6),
            "tp": best["tp"], "fp": best["fp"]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", required=True)
    ap.add_argument("--predictions", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--auc-variants", required=True,
                    help="the arm's auc-variants file; every AUC here is checked against it")
    ap.add_argument("--out")
    args = ap.parse_args()

    grades = {str(r["id"]): truth_grade(r) for r in read_jsonl(Path(args.cases))}
    agg = defaultdict(lambda: {"block": 0.0, "allow": 1.0, "confirm": 0.0})
    for row in read_jsonl(Path(args.predictions)):
        probs = row.get("probabilities") or {}
        e = agg[str(row["case_id"])]
        e["block"] = max(e["block"], float(probs.get("disposition.block", 0.0)))
        e["confirm"] = max(e["confirm"], float(probs.get("disposition.confirm", 0.0)))
        e["allow"] = min(e["allow"], float(probs.get("disposition.allow", 1.0)))

    scored = [(grades.get(cid), e) for cid, e in agg.items()]
    scored = [(g, e) for g, e in scored if g in ("A", "B", "D")]
    labels = [g in ("A", "B") for g, _ in scored]

    pinned = json.loads(Path(args.auc_variants).read_text())["auc"]
    out = {"kind": "defenseclaw-system-one-recall-by-ranking-variable", "schema_version": "1",
           "model": args.label, "predictions": args.predictions,
           "positives_A_B": sum(labels), "negatives_D": len(labels) - sum(labels),
           "fpr_caps": [float(c) for c in CAPS], "by_variable": {}}
    for name, fn in VARIANTS.items():
        scores = [fn(e) for _, e in scored]
        a = auc(scores, labels)
        if abs(a - pinned[name]) > 5e-12:
            raise SystemExit(f"ABORT: {name} AUC {a!r} disagrees with {args.auc_variants} "
                             f"({pinned[name]!r}); the two figures are not one definition")
        out["by_variable"][name] = {
            "roc_auc": a, "distinct_scores": len(set(scores)),
            **{f"recall_at_fpr_{c}": at_cap(scores, labels, float(c)) for c in CAPS}}
    print(json.dumps(out, indent=2, sort_keys=True))
    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
