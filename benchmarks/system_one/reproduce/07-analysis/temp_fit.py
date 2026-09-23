"""Per-primitive vs single global temperature, fitted on our own 324-row measurements.

OpenJev -- the rank-1 model on this board -- serves separate calibration temperatures per
primitive (READOUT_T=0.85 for choice and score, READOUT_NOUL_T=1.829074 with
READOUT_NOUL_BIAS=0 for noul). Nimble fits one temperature across all primitives, and its
own PR #7 records that this made its 64 rating questions worse. This tests both on the
same rows for every Gemma 4 arm we measured.

Temperature scaling on a renormalized candidate distribution is exact: softmax(log(p)/T)
equals softmax(z/T) for the original candidate logits z, because the missing log-partition
term is a constant inside the softmax. So no re-running is needed -- the recorded
distributions are sufficient.

Temperature scaling cannot move an argmax, so accuracy is invariant by construction. What
it can fix is NLL, Brier and ECE, i.e. whether the score is usable as a ranking and
thresholding variable at all.
"""

import json
import math
import sys
from pathlib import Path

GRID = [math.exp(x) for x in [(-1.20 + 0.02 * i) for i in range(int((3.40 + 1.20) / 0.02) + 1)]]


def load(path):
    rows = [json.loads(l) for l in (Path(path) / "rows.jsonl").read_text().splitlines() if l.strip()]
    settings = json.loads((Path(path) / "settings.json").read_text())
    return rows, settings


def gold_key(target, kind):
    return str(target).lower() if kind == "noul" else str(target)


def rescale(probabilities, temperature):
    keys = list(probabilities)
    scaled = [math.log(max(probabilities[k], 1e-300)) / temperature for k in keys]
    top = max(scaled)
    exp = [math.exp(v - top) for v in scaled]
    total = sum(exp)
    return {k: e / total for k, e in zip(keys, exp)}


def metrics(rows, temperatures, bins=15):
    records = []
    for row in rows:
        temperature = temperatures.get(row["kind"], 1.0)
        p = rescale(row["probabilities"], temperature)
        gold = gold_key(row["target"], row["kind"])
        best = max(p, key=p.get)
        records.append({"kind": row["kind"], "correct": best == gold, "top": p[best],
                        "nll": -math.log(max(p[gold], 1e-15)),
                        "brier": sum((v - int(k == gold)) ** 2 for k, v in p.items())})
    out = {}
    for kind in ("all", "choice", "noul", "score"):
        chosen = [r for r in records if kind == "all" or r["kind"] == kind]
        if not chosen:
            continue
        edges = [i / bins for i in range(bins + 1)]
        ece = 0.0
        for low, high in zip(edges[:-1], edges[1:]):
            bucket = [r for r in chosen if low < r["top"] <= high]
            if bucket:
                ece += (len(bucket) / len(chosen)) * abs(
                    sum(r["correct"] for r in bucket) / len(bucket)
                    - sum(r["top"] for r in bucket) / len(bucket))
        out[kind] = {"count": len(chosen), "correct": sum(r["correct"] for r in chosen),
                     "accuracy": sum(r["correct"] for r in chosen) / len(chosen),
                     "mean_nll": sum(r["nll"] for r in chosen) / len(chosen),
                     "mean_brier": sum(r["brier"] for r in chosen) / len(chosen),
                     "mean_top_probability": sum(r["top"] for r in chosen) / len(chosen),
                     "ece_15bin": ece}
    return out


def fit(rows, kinds):
    """Minimize NLL on the given rows over the shared grid, for the given set of kinds."""
    subset = [r for r in rows if r["kind"] in kinds]
    if not subset:
        return 1.0
    best = (float("inf"), 1.0)
    for temperature in GRID:
        total = 0.0
        for row in subset:
            p = rescale(row["probabilities"], temperature)
            total += -math.log(max(p[gold_key(row["target"], row["kind"])], 1e-15))
        if total < best[0]:
            best = (total, temperature)
    return best[1]


def main():
    out = {"kind": "gemma4jev-temperature-calibration",
           "note": ("temperatures fitted by NLL on even-indexed rows, reported on odd-indexed rows; "
                    "accuracy is invariant under temperature scaling by construction"),
           "openjev_served_temperatures": {"choice_and_score": 0.85, "noul": 1.829074, "noul_bias": 0},
           "nimble_fitted_single_temperature": 2.179078721266035,
           "arms": {}}
    for path in sys.argv[1:-1]:
        rows, settings = load(path)
        fit_rows = [r for i, r in enumerate(rows) if i % 2 == 0]
        test_rows = [r for i, r in enumerate(rows) if i % 2 == 1]
        global_t = fit(fit_rows, {"choice", "noul", "score"})
        per_kind = {kind: fit(fit_rows, {kind}) for kind in ("choice", "noul", "score")}
        out["arms"][Path(path).name] = {
            "repo": settings["repo"], "revision": settings["revision"], "permute": settings["permute"],
            "fitted_global_temperature": global_t,
            "fitted_per_primitive_temperatures": per_kind,
            "held_out_uncalibrated": metrics(test_rows, {}),
            "held_out_single_global_temperature": metrics(test_rows, {k: global_t for k in per_kind}),
            "held_out_per_primitive_temperatures": metrics(test_rows, per_kind),
            "held_out_openjev_served_temperatures": metrics(
                test_rows, {"choice": 0.85, "score": 0.85, "noul": 1.829074}),
        }
    Path(sys.argv[-1]).write_text(json.dumps(out, indent=2) + "\n")
    print("%-22s %-7s %-22s | %-28s | %-28s | %s" % (
        "arm", "globalT", "per-primitive T", "uncal (ece/nll/brier)",
        "globalT (ece/nll/brier)", "per-prim (ece/nll/brier)"))
    for name, v in out["arms"].items():
        u, g, p = (v["held_out_uncalibrated"]["all"], v["held_out_single_global_temperature"]["all"],
                   v["held_out_per_primitive_temperatures"]["all"])
        print("%-22s %-7.3f %-22s | %6.4f %7.4f %6.4f       | %6.4f %7.4f %6.4f       | %6.4f %7.4f %6.4f" % (
            name, v["fitted_global_temperature"],
            "/".join("%.2f" % v["fitted_per_primitive_temperatures"][k] for k in ("choice", "noul", "score")),
            u["ece_15bin"], u["mean_nll"], u["mean_brier"],
            g["ece_15bin"], g["mean_nll"], g["mean_brier"],
            p["ece_15bin"], p["mean_nll"], p["mean_brier"]))
    for name, v in out["arms"].items():
        print("  %s per-kind ECE: uncal %s -> globalT %s -> per-prim %s" % (
            name,
            {k: round(v["held_out_uncalibrated"][k]["ece_15bin"], 4) for k in ("choice", "noul", "score")},
            {k: round(v["held_out_single_global_temperature"][k]["ece_15bin"], 4) for k in ("choice", "noul", "score")},
            {k: round(v["held_out_per_primitive_temperatures"][k]["ece_15bin"], 4) for k in ("choice", "noul", "score")}))


if __name__ == "__main__":
    main()
