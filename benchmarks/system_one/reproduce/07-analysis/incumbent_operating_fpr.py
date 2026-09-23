#!/usr/bin/env python3
"""The incumbent cascade's own recall at its own block false-positive rate.

The site's recall artifacts measure every row at four fixed caps: 0.001, 0.005, 0.01 and 0.05.
None of them is OpenJev's own block false-positive rate of 0.00384502, so a row compared against
OpenJev "at its own operating point" had no incumbent number to be compared with, and the nearest
published point, 0.288991, belongs to the 0.5% cap and is a looser threshold.

This measures OpenJev at that cap on the leaderboard ranking variable, with the same threshold
rule the published recall artifacts use.  It is self-validating: the same code path must reproduce
OpenJev's published risk AUC and its published 0.005-cap point exactly, or it aborts.  Those two
reproductions are what make the new point trustworthy.
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

# what the published artifacts already record for this arm, and what this must reproduce
PINNED_AUC = 0.937432
PINNED_005 = {"recall": 0.288991, "achieved_fpr": 0.004732, "tp": 126, "fp": 16}
CAPS = ["0.001", "0.00384502", "0.005", "0.01", "0.05"]
VARIABLE = "risk = 1 - disposition.allow (max over events)"


def auc(scores, labels):
    pos = [s for s, l in zip(scores, labels) if l]
    neg = sorted(s for s, l in zip(scores, labels) if not l)
    wins = ties = 0
    for s in pos:
        wins += bisect.bisect_left(neg, s)
        ties += bisect.bisect_right(neg, s) - bisect.bisect_left(neg, s)
    return (wins + 0.5 * ties) / (len(pos) * len(neg))


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
    ap.add_argument("--operating-fpr", required=True, type=float)
    ap.add_argument("--out")
    args = ap.parse_args()

    grades = {str(r["id"]): truth_grade(r) for r in read_jsonl(Path(args.cases))}
    agg = defaultdict(lambda: 1.0)
    for row in read_jsonl(Path(args.predictions)):
        p = row.get("probabilities") or {}
        cid = str(row["case_id"])
        agg[cid] = min(agg[cid], float(p.get("disposition.allow", 1.0)))
    pairs = [(grades.get(c), 1 - a) for c, a in agg.items()]
    pairs = [(g, s) for g, s in pairs if g in ("A", "B", "D")]
    labels = [g in ("A", "B") for g, _ in pairs]
    scores = [s for _, s in pairs]

    a = auc(scores, labels)
    if abs(a - PINNED_AUC) > 5e-7:
        raise SystemExit(f"ABORT: risk AUC {a!r} does not reproduce the published {PINNED_AUC}")
    points = {f"recall_at_fpr_{c}": at_cap(scores, labels, float(c)) for c in CAPS}
    got = points["recall_at_fpr_0.005"]
    for k, v in PINNED_005.items():
        if abs(got[k] - v) > 5e-7:
            raise SystemExit(f"ABORT: 0.005-cap {k} {got[k]!r} does not reproduce the published "
                             f"{v!r}; the threshold rule here is not the published one")
    out = {"kind": "defenseclaw-system-one-incumbent-recall-at-operating-fpr",
           "schema_version": "1", "model": "OpenJev", "predictions": args.predictions,
           "score_variable": VARIABLE, "operating_block_fpr": args.operating_fpr,
           "positives_A_B": sum(labels), "negatives_D": len(labels) - sum(labels),
           "roc_auc": a, "distinct_scores": len(set(scores)),
           "fpr_caps": [float(c) for c in CAPS],
           "reproduces_published": {"roc_auc": PINNED_AUC, "recall_at_fpr_0.005": PINNED_005},
           **points}
    print(json.dumps(out, indent=2, sort_keys=True))
    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
