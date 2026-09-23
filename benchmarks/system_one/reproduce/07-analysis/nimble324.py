"""Re-run Bespoke-Nimble-9B on the same 324-row holdout, for a calibration comparison.

Two reasons this is needed rather than quoted. First, it reproduces the published
292/324 with our own harness, which validates the harness. Second, the published
artifact records only correct counts, and the question at issue is calibration: jevify
trained on soft target distributions with a KL objective and reports ECE 0.234 -> 0.032,
while Nimble trained on hard labels with cross-entropy. Comparing ECE needs Nimble's
per-row distributions on the same rows.

Serving is the other agent's already-written nimble_shim.NimblePredictor, unmodified, so
the prompt and readout are Nimble's own published contract (its parallel_schema.py
digest is checked against schema_config.json inside that class).
"""

import argparse
import gc
import hashlib
import json
import sys
import time
from collections import Counter
from pathlib import Path

import torch

sys.path.insert(0, "$WORK/sysone")
sys.path.insert(0, "$WORK/sysone/nimble")
sys.path.insert(0, "$WORK/g4j")

from nimble_shim import FITTED_TEMPERATURES, MODEL_ID, NimblePredictor, build_schema, serialize  # noqa: E402

DATA = Path("$WORK/sysone/nimble/data/eval.jsonl")


def assess(probabilities, target, kind):
    """Identical to nimble.evaluation.evaluate_pilot.assess for the fields used here."""
    import math
    if (not probabilities or any(not math.isfinite(p) or not 0 <= p <= 1 for p in probabilities.values())
            or not math.isclose(sum(probabilities.values()), 1, abs_tol=1e-6)):
        raise ValueError("Invalid probability distribution")
    if kind == "noul":
        if type(target) is not bool:
            raise ValueError("Noul reference must be boolean")
        gold = str(target).lower()
    elif kind == "score":
        if type(target) is not int:
            raise ValueError("Score reference must be an integer level")
        gold = str(target)
    else:
        gold = str(target)
    if gold not in probabilities:
        raise ValueError("Reference target absent from candidates")
    best = max(probabilities, key=probabilities.get)
    prediction = (best == "true") if kind == "noul" else int(best) if kind == "score" else best
    out = {"prediction": prediction, "correct": best == gold,
           "reference_probability": probabilities[gold], "top_probability": probabilities[best],
           "negative_log_likelihood": -math.log(max(probabilities[gold], 1e-15)),
           "multiclass_brier": sum((p - int(k == gold)) ** 2 for k, p in probabilities.items())}
    if kind == "score":
        expected = sum(int(k) * p for k, p in probabilities.items())
        out.update(expected_score=expected, absolute_score_error=abs(expected - target))
    return out


def ece_from(records, bins=15):
    edges = [i / bins for i in range(bins + 1)]
    if not records:
        return None
    value = 0.0
    for low, high in zip(edges[:-1], edges[1:]):
        chosen = [r for r in records if low < r["top_probability"] <= high]
        if not chosen:
            continue
        value += (len(chosen) / len(records)) * abs(
            sum(r["correct"] for r in chosen) / len(chosen)
            - sum(r["top_probability"] for r in chosen) / len(chosen))
    return value


def summarize(rows, temperature_key):
    out = {}
    for kind in ("all", "choice", "noul", "score"):
        chosen = [r for r in rows if kind == "all" or r["kind"] == kind]
        if not chosen:
            continue
        m = [r[temperature_key] for r in chosen]
        group = {"count": len(m), "correct": sum(x["correct"] for x in m)}
        group["accuracy"] = group["correct"] / group["count"]
        group["mean_nll"] = sum(x["negative_log_likelihood"] for x in m) / len(m)
        group["mean_brier"] = sum(x["multiclass_brier"] for x in m) / len(m)
        group["mean_top_probability"] = sum(x["top_probability"] for x in m) / len(m)
        group["mean_reference_probability"] = sum(x["reference_probability"] for x in m) / len(m)
        group["ece_15bin"] = ece_from(m)
        out[kind] = group
    return out


def softmax(values, temperature):
    import math
    top = max(v / temperature for v in values)
    exp = [math.exp(v / temperature - top) for v in values]
    total = sum(exp)
    return [e / total for e in exp]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--device", default="cuda:0")
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    raw = DATA.read_bytes()
    rows = [json.loads(line) for line in raw.decode().splitlines() if line.strip()]
    fitted = FITTED_TEMPERATURES[(MODEL_ID, "93ec5d6ff1a9cd31d6cc0e0c58d312465d36de7c")]
    predictor = NimblePredictor(args.checkpoint, device=args.device, temperature=1.0)

    output = Path(args.out_dir)
    output.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    records = []
    for row in rows:
        question = row["input"]["questions"]["decision"]
        kind = question["type"]
        schema = build_schema(row["input"]["questions"])
        names, logit_rows, tokens = predictor._field_logits(serialize(row["input"]["state"]), schema)
        assert names == ["decision"], names
        logits = logit_rows[0]
        keys = list(schema["decision"]["choices"])
        keys = [str(k).lower() if isinstance(k, bool) else k for k in keys]
        record = {"id": row["id"], "kind": kind, "family": row["source_family"],
                  "target": row["reference"]["target"], "prompt_tokens": tokens, "logits": logits}
        for label, temperature in (("t1", 1.0), ("t_fitted", fitted)):
            probabilities = dict(zip(keys, softmax(logits, temperature)))
            record[label] = assess(probabilities, row["reference"]["target"], kind)
            record[label]["probabilities"] = probabilities
        record["selected_letter"] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[max(range(len(logits)), key=logits.__getitem__)]
        records.append(record)
        if len(records) % 50 == 0 or len(records) == len(rows):
            print(f"nimble: {len(records)}/{len(rows)} ({time.perf_counter() - started:.0f}s)", flush=True)
    del predictor
    gc.collect()
    torch.cuda.empty_cache()

    report = {
        "model": MODEL_ID, "adapter_revision": "93ec5d6ff1a9cd31d6cc0e0c58d312465d36de7c",
        "checkpoint": args.checkpoint, "dataset": str(DATA),
        "dataset_sha256": hashlib.sha256(raw).hexdigest(), "count": len(rows),
        "fitted_temperature": fitted,
        "note": ("the 324 rows are Nimble's own held-out validation split from the same generator as its "
                 "2,676 training rows, so Nimble is in-distribution here while the Gemma arms are not"),
        "wall_seconds": time.perf_counter() - started,
        "total_prompt_tokens": sum(r["prompt_tokens"] for r in records),
        "selected_letter_counts_choice": dict(sorted(Counter(
            r["selected_letter"] for r in records if r["kind"] == "choice").items())),
        "summary_temperature_1": summarize(records, "t1"),
        "summary_temperature_fitted": summarize(records, "t_fitted"),
    }
    (output / "rows.jsonl").write_text("".join(json.dumps(r, allow_nan=False) + "\n" for r in records))
    (output / "results.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k.startswith("summary")}, indent=2))


if __name__ == "__main__":
    main()
