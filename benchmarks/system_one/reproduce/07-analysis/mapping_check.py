"""Is the disposition mapping faithful, or is the scalar head being read in an inverted way?

A block-only recall of 0.099 with a ROC AUC below 0.5 could mean either
  (a) the mapping is inverted / mis-wired, or
  (b) the model is correctly wired but genuinely mis-ranks our corpus.
These are distinguishable without any GPU: compare the emitted disposition probabilities
against the scorer's own truth grades on the finished prediction file.

If the mapping were inverted, P(block) would be HIGHER on benign grade-D cases than on
unsafe grade-A cases. If it is faithful but weak, P(block) is ordered correctly yet rarely
large enough to win the argmax.
"""
import argparse
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, "$WORK/defenseclaw-system-one/benchmarks/scripts")
from benchmark_inventory_system_one_sources import read_jsonl, truth_grade  # noqa: E402


def quantiles(values):
    if not values:
        return {}
    ordered = sorted(values)
    pick = lambda q: round(ordered[min(len(ordered) - 1, max(0, int(q * len(ordered)) - 1))], 6)
    return {"n": len(values), "mean": round(statistics.fmean(values), 6),
            "p05": pick(0.05), "p50": pick(0.50), "p95": pick(0.95), "max": round(max(values), 6)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--out")
    args = parser.parse_args()

    grades = {str(row["id"]): truth_grade(row) for row in read_jsonl(Path(args.cases))}

    # Per-case aggregation matching the scorer: max over events.
    per_case = defaultdict(lambda: {"block": 0.0, "confirm": 0.0, "allow": 1.0, "risk": 0.0, "actions": []})
    for row in read_jsonl(Path(args.predictions)):
        probs = row.get("probabilities") or {}
        entry = per_case[str(row["case_id"])]
        block = float(probs.get("disposition.block", 0.0))
        confirm = float(probs.get("disposition.confirm", 0.0))
        allow = float(probs.get("disposition.allow", 1.0))
        entry["block"] = max(entry["block"], block)
        entry["confirm"] = max(entry["confirm"], confirm)
        entry["allow"] = min(entry["allow"], allow)
        entry["risk"] = max(entry["risk"], 1.0 - allow)
        entry["actions"].append(row.get("action"))

    by_grade = defaultdict(lambda: defaultdict(list))
    action_by_grade = defaultdict(lambda: defaultdict(int))
    for case_id, entry in per_case.items():
        grade = grades.get(case_id, "?")
        by_grade[grade]["p_block"].append(entry["block"])
        by_grade[grade]["p_confirm"].append(entry["confirm"])
        by_grade[grade]["risk"].append(entry["risk"])
        worst = "allow"
        for action in entry["actions"]:
            if action == "block":
                worst = "block"
            elif action == "confirm" and worst != "block":
                worst = "confirm"
        action_by_grade[grade][worst] += 1

    report = {
        "predictions": args.predictions,
        "grade_legend": {"A": "truth=block (unsafe)", "B": "truth=confirm (unsafe)",
                         "C": "diagnostic, excluded from scoring", "D": "truth=allow (benign)"},
        "by_grade": {grade: {metric: quantiles(values) for metric, values in sorted(metrics.items())}
                     for grade, metrics in sorted(by_grade.items())},
        "predicted_action_by_grade": {g: dict(sorted(v.items())) for g, v in sorted(action_by_grade.items())},
    }

    a = report["by_grade"].get("A", {}).get("p_block", {})
    d = report["by_grade"].get("D", {}).get("p_block", {})
    ra = report["by_grade"].get("A", {}).get("risk", {})
    rd = report["by_grade"].get("D", {}).get("risk", {})
    report["verdict"] = {
        "mean_p_block_unsafe_A": a.get("mean"),
        "mean_p_block_benign_D": d.get("mean"),
        "p_block_ordered_correctly": (a.get("mean") or 0) > (d.get("mean") or 0),
        "mean_risk_unsafe_A": ra.get("mean"),
        "mean_risk_benign_D": rd.get("mean"),
        "risk_ordered_correctly": (ra.get("mean") or 0) > (rd.get("mean") or 0),
        "interpretation": None,
    }
    v = report["verdict"]
    if v["p_block_ordered_correctly"] and v["risk_ordered_correctly"]:
        v["interpretation"] = ("Mapping is faithful and correctly oriented: both P(block) and "
                               "risk are higher on unsafe cases than benign ones. Low block recall "
                               "is the model under-producing block, not an inverted readout.")
    elif v["p_block_ordered_correctly"] and not v["risk_ordered_correctly"]:
        v["interpretation"] = ("P(block) is oriented correctly but risk = 1 - P(allow) is not, "
                               "because the confirm mass dominates on benign cases. The disposition "
                               "mapping is faithful; the AUC below 0.5 comes from the risk variable "
                               "absorbing benign confirm mass, not from a wiring error.")
    else:
        v["interpretation"] = ("P(block) is NOT higher on unsafe cases: investigate the mapping "
                               "before quoting any metric from this run.")

    print(json.dumps(report, indent=2, sort_keys=True))
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
