"""Quantify eager-vs-sdpa divergence on this checkpoint, on identical request bodies.

Worth measuring rather than asserting: `jev/model.py` hardcodes `attn_implementation="sdpa"`,
so the published 2B and 9B arms ran the sdpa path, while this 27B was required to run eager.
That makes attention implementation a real difference between arms, and the size of it
decides whether it matters. Elsewhere in this programme an sdpa/eager gap of 8.99e-3 was
already enough to fail tolerance.

Compares the two selftest dumps field by field over every emitted probability.
"""
import argparse
import json
from pathlib import Path


def flatten(answers):
    """Every scalar probability the decision is read from, as a flat dict."""
    out = {}
    for field, value in sorted((answers or {}).items()):
        kind = value.get("type")
        if kind == "choice":
            for option, probability in sorted(value.get("probabilities", {}).items()):
                out[f"{field}.{option}"] = float(probability)
            out[f"{field}.confidence"] = float(value.get("confidence", 0.0))
        elif kind == "score":
            for bucket, probability in sorted(value.get("probabilities", {}).items()):
                out[f"{field}.{bucket}"] = float(probability)
            out[f"{field}.score"] = float(value.get("score", 0.0))
        elif kind == "noul":
            out[f"{field}.noul"] = float(value.get("noul", 0.0))
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--a", required=True, help="selftest json (eager)")
    parser.add_argument("--b", required=True, help="selftest json (sdpa)")
    parser.add_argument("--label-a", default="eager")
    parser.add_argument("--label-b", default="sdpa")
    parser.add_argument("--tolerance", type=float, default=1e-3)
    parser.add_argument("--out")
    args = parser.parse_args()

    left = json.loads(Path(args.a).read_text())
    right = json.loads(Path(args.b).read_text())

    def key_of(result):
        return (str(result.get("case_id")), result.get("event_index"))

    left_by = {key_of(r): r for r in left["results"]}
    right_by = {key_of(r): r for r in right["results"]}
    shared = sorted(set(left_by) & set(right_by), key=lambda k: (k[0], k[1] or 0))
    if not shared:
        raise SystemExit("ABORT: no shared requests between the two dumps")

    worst = {"delta": 0.0, "field": None, "request": None,
             f"{args.label_a}": None, f"{args.label_b}": None}
    deltas = []
    flips = []
    for key in shared:
        a_flat = flatten(left_by[key].get("answers"))
        b_flat = flatten(right_by[key].get("answers"))
        for field in sorted(set(a_flat) & set(b_flat)):
            delta = abs(a_flat[field] - b_flat[field])
            deltas.append(delta)
            if delta > worst["delta"]:
                worst = {"delta": delta, "field": field, "request": list(key),
                         args.label_a: a_flat[field], args.label_b: b_flat[field]}
        a_choice = (left_by[key].get("answers") or {}).get("disposition", {}).get("choice")
        b_choice = (right_by[key].get("answers") or {}).get("disposition", {}).get("choice")
        if a_choice != b_choice:
            flips.append({"request": list(key), args.label_a: a_choice, args.label_b: b_choice})

    deltas.sort()
    report = {
        "kind": "openjev-qwen-27b-attention-implementation-agreement",
        "compared": {args.label_a: args.a, args.label_b: args.b},
        "requests_compared": len(shared),
        "scalar_fields_compared": len(deltas),
        "tolerance": args.tolerance,
        "max_abs_delta": worst["delta"],
        "worst_field": worst,
        "p50_abs_delta": deltas[len(deltas) // 2],
        "p95_abs_delta": deltas[int(len(deltas) * 0.95)],
        "mean_abs_delta": sum(deltas) / len(deltas),
        "argmax_disposition_flips": len(flips),
        "argmax_disposition_flip_detail": flips,
        "within_tolerance": worst["delta"] <= args.tolerance,
        "batch_size": {args.label_a: left.get("batch_size"), args.label_b: right.get("batch_size")},
        "attn": {args.label_a: left.get("attn_implementation"),
                 args.label_b: right.get("attn_implementation")},
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                  encoding="utf-8")
        print("wrote", args.out)


if __name__ == "__main__":
    main()
