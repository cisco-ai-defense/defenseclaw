"""Permutation averaging, measured on runs we already have.

OpenJev's shipped helper exposes READOUT_PERMS with the comment
"4 ~= +16 pts acc, 4x cost", and its card says the model is *trained* to stay
consistent when options are reordered. That is an inference-time lever that needs no
training. We already scored the 324-row holdout under two letterings (the dataset's
order and the reverse), so averaging those two distributions per row is a free
two-permutation estimate of what that lever buys on a Gemma 4 checkpoint.
"""

import json
import math
import sys
from pathlib import Path


def load(path):
    rows = [json.loads(l) for l in (Path(path) / "rows.jsonl").read_text().splitlines() if l.strip()]
    return {r["id"]: r for r in rows}, json.loads((Path(path) / "settings.json").read_text())


def gold_key(target, kind):
    if kind == "noul":
        return str(target).lower()
    return str(target)


def ece_from(records, bins=15):
    edges = [i / bins for i in range(bins + 1)]
    if not records:
        return None
    value = 0.0
    for low, high in zip(edges[:-1], edges[1:]):
        chosen = [r for r in records if low < r["top"] <= high]
        if not chosen:
            continue
        value += (len(chosen) / len(records)) * abs(
            sum(r["correct"] for r in chosen) / len(chosen) - sum(r["top"] for r in chosen) / len(chosen))
    return value


def assess_all(rows):
    out = {}
    for kind in ("all", "choice", "noul", "score"):
        chosen = [r for r in rows if kind == "all" or r["kind"] == kind]
        if not chosen:
            continue
        out[kind] = {
            "count": len(chosen), "correct": sum(r["correct"] for r in chosen),
            "accuracy": sum(r["correct"] for r in chosen) / len(chosen),
            "mean_nll": sum(r["nll"] for r in chosen) / len(chosen),
            "mean_brier": sum(r["brier"] for r in chosen) / len(chosen),
            "mean_top_probability": sum(r["top"] for r in chosen) / len(chosen),
            "ece_15bin": ece_from(chosen)}
    return out


def main():
    base, base_settings = load(sys.argv[1])
    perm, perm_settings = load(sys.argv[2])
    if base_settings["repo"] != perm_settings["repo"]:
        raise SystemExit("different checkpoints")
    rows = []
    for row_id in base:
        a, b = base[row_id], perm[row_id]
        keys = list(a["probabilities"])
        if set(keys) != set(b["probabilities"]):
            raise SystemExit("candidate keys differ")
        averaged = {k: (a["probabilities"][k] + b["probabilities"][k]) / 2 for k in keys}
        total = sum(averaged.values())
        averaged = {k: v / total for k, v in averaged.items()}
        gold = gold_key(a["target"], a["kind"])
        best = max(averaged, key=averaged.get)
        rows.append({"id": row_id, "kind": a["kind"], "family": a["family"],
                     "correct": best == gold, "top": averaged[best],
                     "nll": -math.log(max(averaged[gold], 1e-15)),
                     "brier": sum((p - int(k == gold)) ** 2 for k, p in averaged.items()),
                     "single_order_correct": a["correct"], "reversed_order_correct": b["correct"]})
    single = [{**r, "correct": r["single_order_correct"], "top": r["top"]} for r in rows]
    report = {
        "repo": base_settings["repo"], "revision": base_settings["revision"],
        "permutations_averaged": 2, "orders": [base_settings["permute"], perm_settings["permute"]],
        "note": ("two letterings only; OpenJev's helper comment quotes 4 letterings. Probabilities are "
                 "averaged per candidate key, then renormalized, then scored with the same accounting."),
        "averaged": assess_all(rows),
        "single_order": assess_all(single),
        "gain": {},
        "recovered_by_averaging": sum((not r["single_order_correct"]) and r["correct"] for r in rows),
        "lost_by_averaging": sum(r["single_order_correct"] and not r["correct"] for r in rows),
        "either_order_correct": sum(r["single_order_correct"] or r["reversed_order_correct"] for r in rows),
        "both_orders_correct": sum(r["single_order_correct"] and r["reversed_order_correct"] for r in rows),
    }
    for kind in report["averaged"]:
        report["gain"][kind] = {
            "accuracy_delta": report["averaged"][kind]["accuracy"] - report["single_order"][kind]["accuracy"],
            "correct_delta": report["averaged"][kind]["correct"] - report["single_order"][kind]["correct"]}
    print(json.dumps(report, indent=2))
    Path(sys.argv[3]).write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
