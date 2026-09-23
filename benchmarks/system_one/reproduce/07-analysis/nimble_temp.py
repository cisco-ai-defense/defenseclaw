"""Per-primitive vs single temperature on Bespoke-Nimble-9B's own 324-row logits.

Nimble ships ONE fitted temperature (2.179078721266035) for all three primitives, and its
own PR #7 records that this made its 64 rating questions worse. OpenJev, the rank-1 model
here, serves separate temperatures per primitive. This fits both on Nimble's raw candidate
logits from our rerun and reports them on a held-out half.
"""

import json
import math
from pathlib import Path

ROWS = Path("$WORK/g4j/out/holdout/nimble-9b/rows.jsonl")
SHIPPED = 2.179078721266035
GRID = [math.exp(-1.2 + 0.02 * i) for i in range(int(4.6 / 0.02) + 1)]


def keys_for(row):
    n = len(row["logits"])
    if row["kind"] == "noul":
        return ["false", "true"]
    if row["kind"] == "score":
        return [str(i) for i in range(n)]
    return list(row["t1"]["probabilities"])


def distribution(row, temperature):
    z = [v / temperature for v in row["logits"]]
    top = max(z)
    exp = [math.exp(v - top) for v in z]
    total = sum(exp)
    return dict(zip(keys_for(row), [e / total for e in exp]))


def gold(row):
    return str(row["target"]).lower() if row["kind"] == "noul" else str(row["target"])


def metrics(rows, temperatures, bins=15):
    records = []
    for row in rows:
        p = distribution(row, temperatures.get(row["kind"], 1.0))
        g = gold(row)
        best = max(p, key=p.get)
        records.append({"kind": row["kind"], "correct": best == g, "top": p[best],
                        "nll": -math.log(max(p[g], 1e-15)),
                        "brier": sum((v - int(k == g)) ** 2 for k, v in p.items())})
    out = {}
    for kind in ("all", "choice", "noul", "score"):
        chosen = [r for r in records if kind == "all" or r["kind"] == kind]
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
                     "ece_15bin": ece, "mean_top_probability": sum(r["top"] for r in chosen) / len(chosen)}
    return out


def fit(rows, kinds):
    subset = [r for r in rows if r["kind"] in kinds]
    best = (float("inf"), 1.0)
    for t in GRID:
        total = sum(-math.log(max(distribution(r, t)[gold(r)], 1e-15)) for r in subset)
        if total < best[0]:
            best = (total, t)
    return best[1]


rows = [json.loads(l) for l in ROWS.read_text().splitlines() if l.strip()]
fit_rows = [r for i, r in enumerate(rows) if i % 2 == 0]
test_rows = [r for i, r in enumerate(rows) if i % 2 == 1]
single = fit(fit_rows, {"choice", "noul", "score"})
per_kind = {k: fit(fit_rows, {k}) for k in ("choice", "noul", "score")}
report = {
    "model": "bespokelabs/Bespoke-Nimble-9B",
    "adapter_revision": "93ec5d6ff1a9cd31d6cc0e0c58d312465d36de7c",
    "shipped_single_temperature": SHIPPED,
    "refitted_single_temperature": single,
    "refitted_per_primitive_temperatures": per_kind,
    "held_out_T1": metrics(test_rows, {}),
    "held_out_shipped_single": metrics(test_rows, {k: SHIPPED for k in per_kind}),
    "held_out_refitted_single": metrics(test_rows, {k: single for k in per_kind}),
    "held_out_per_primitive": metrics(test_rows, per_kind),
}
Path("$WORK/g4j/out/nimble-temp-calibration.json").write_text(json.dumps(report, indent=2) + "\n")
print("shipped single T=%.6f  refitted single T=%.4f  per-primitive %s" % (
    SHIPPED, single, {k: round(v, 4) for k, v in per_kind.items()}))
print("%-26s %8s %8s %8s | %s" % ("held-out config", "ece", "nll", "brier", "per-kind ECE choice/noul/score"))
for label in ("held_out_T1", "held_out_shipped_single", "held_out_refitted_single", "held_out_per_primitive"):
    m = report[label]
    print("%-26s %8.4f %8.4f %8.4f | %.4f / %.4f / %.4f" % (
        label.removeprefix("held_out_"), m["all"]["ece_15bin"], m["all"]["mean_nll"], m["all"]["mean_brier"],
        m["choice"]["ece_15bin"], m["noul"]["ece_15bin"], m["score"]["ece_15bin"]))
