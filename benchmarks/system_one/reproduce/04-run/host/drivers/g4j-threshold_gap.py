"""How much of each arm's block-only F1 gap is the threshold rather than the model?

For every ranked arm this compares the block-only F1 the arm actually ships -- the
scorer's own disposition decision, aggregated the scorer's own way -- with the best
block-only F1 the same per-case risk score can reach under a single global threshold.
The difference is what re-thresholding alone would buy, with no new model and no
training. An FPR-constrained optimum is also reported, because a security gate cannot
spend arbitrary false positives to buy F1.

Everything is read from settled prediction files through the shared scorer's own
`aggregate_system` and `case_truth`, so the labels and case aggregation are identical
to the ranked table.
"""

import argparse
import json
import sys
from pathlib import Path

REPO = "$WORK/defenseclaw-system-one"
sys.path.insert(0, REPO)
sys.path.insert(0, REPO + "/benchmarks/scripts")

from benchmark_inventory_system_one_sources import read_jsonl, sha256_file, truth_grade  # noqa: E402
from benchmark_score_system_one import aggregate_system, case_truth  # noqa: E402

FPR_CAPS = [0.001, 0.005, 0.01, 0.05, None]


def f1_at(labels, scores, threshold):
    tp = fp = fn = tn = 0
    for label, score in zip(labels, scores):
        predicted = score >= threshold
        if label and predicted:
            tp += 1
        elif label and not predicted:
            fn += 1
        elif not label and predicted:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    negatives = fp + tn
    return {"threshold": threshold, "f1": f1, "precision": precision, "recall": recall,
            "false_positive_rate": fp / negatives if negatives else None,
            "confusion": {"true_positive": tp, "false_positive": fp,
                          "false_negative": fn, "true_negative": tn}}


def sweep(labels, scores):
    return [f1_at(labels, scores, t) for t in sorted({s for s in scores} | {max(scores) + 1e-12})]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", required=True)
    parser.add_argument("--arm", action="append", required=True, metavar="LABEL=PATH[,PATH...]")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    cases = {str(row["id"]): row for row in read_jsonl(Path(args.cases))}
    scorable = [cid for cid, row in cases.items() if case_truth(row)[0] is not None]
    labels_by_case = {cid: bool(case_truth(cases[cid])[1]) for cid in scorable}

    report = {"kind": "gemma4jev-threshold-vs-model", "cases_path": args.cases,
              "cases_sha256": sha256_file(Path(args.cases)), "cases": len(cases),
              "scorable_cases": len(scorable), "fpr_caps": FPR_CAPS,
              "note": ("shipped = the scorer's own disposition decision (block iff action == block); "
                       "retuned = single global threshold on the same per-case risk "
                       "(risk = max over events of 1 - disposition.allow)"),
              "arms": {}}

    for spec in args.arm:
        label, paths = spec.split("=", 1)
        rows, digests = [], {}
        for path in paths.split(","):
            p = Path(path)
            if not p.exists():
                report["arms"][label] = {"error": f"missing {path}"}
                rows = None
                break
            digests[path] = sha256_file(p)
            rows.extend(read_jsonl(p))
        if rows is None:
            continue
        for key, per_case in sorted(aggregate_system(rows).items()):
            covered = [c for c in scorable if c in per_case]
            name = f"{label}|{key}"
            if len(covered) != len(scorable):
                report["arms"][name] = {"error": f"covers {len(covered)} of {len(scorable)}",
                                        "prediction_sha256": digests}
                continue
            truth = [labels_by_case[c] for c in covered]
            risk = [float(per_case[c]["risk"]) for c in covered]
            shipped_blocks = [per_case[c]["action"] == "block" for c in covered]
            tp = sum(t and p for t, p in zip(truth, shipped_blocks))
            fp = sum((not t) and p for t, p in zip(truth, shipped_blocks))
            fn = sum(t and not p for t, p in zip(truth, shipped_blocks))
            tn = sum((not t) and not p for t, p in zip(truth, shipped_blocks))
            precision = tp / (tp + fp) if tp + fp else 0.0
            recall = tp / (tp + fn) if tp + fn else 0.0
            shipped = {
                "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
                "precision": precision, "recall": recall,
                "false_positive_rate": fp / (fp + tn) if fp + tn else None,
                "confusion": {"true_positive": tp, "false_positive": fp,
                              "false_negative": fn, "true_negative": tn},
                "decision": "scorer disposition argmax (action == block)",
            }
            points = sweep(truth, risk)
            entry = {"candidate": key, "prediction_sha256": digests,
                     "distinct_risk_values": len({round(r, 12) for r in risk}),
                     "shipped": shipped, "retuned": {}}
            for cap in FPR_CAPS:
                eligible = [p for p in points if cap is None or (p["false_positive_rate"] or 0) <= cap]
                best = max(eligible, key=lambda p: p["f1"]) if eligible else None
                entry["retuned"]["unconstrained" if cap is None else f"fpr_le_{cap}"] = best
            best = entry["retuned"]["unconstrained"]
            entry["threshold_gap_f1"] = (best["f1"] - shipped["f1"]) if best else None
            entry["threshold_share_of_gap_to_0.73773"] = (
                (best["f1"] - shipped["f1"]) / (0.73772791 - shipped["f1"])
                if best and shipped["f1"] < 0.73772791 else None)
            report["arms"][name] = entry

    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    for name, entry in report["arms"].items():
        if "error" in entry:
            print(f"{name}: ERROR {entry['error']}")
            continue
        s, r = entry["shipped"], entry["retuned"]
        print(f"== {name}  distinct_risk={entry['distinct_risk_values']}")
        print("   shipped            f1=%.8f fpr=%.8f p=%.5f r=%.5f" %
              (s["f1"], s["false_positive_rate"], s["precision"], s["recall"]))
        for cap, point in r.items():
            if point:
                print("   retuned %-14s f1=%.8f fpr=%.8f p=%.5f r=%.5f t=%.6f" %
                      (cap, point["f1"], point["false_positive_rate"], point["precision"],
                       point["recall"], point["threshold"]))
        print("   threshold gap (unconstrained) = %+0.8f" % entry["threshold_gap_f1"])


if __name__ == "__main__":
    main()
