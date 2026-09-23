"""Cross-hardware agreement check: L40S (sm_89) published rows vs H200 (sm_90) replay.

Pairs rows on (case_id, event_index), proves the replayed wire body was byte-identical
via the recorded request_sha256, then diffs every emitted scalar.
"""
import argparse
import json
import statistics
from collections import Counter

# Every scalar the prediction schema emits, by dotted path.
PROB_KEYS = [
    "disposition.allow", "disposition.block", "disposition.confirm",
    "risk.0", "risk.1", "risk.2",
    "context_sufficient.false", "context_sufficient.true",
]
DERIVED = ["confidence", "answers.risk", "answers.context_sufficient"]


def get(row, path):
    if path == "confidence":
        return row["confidence"]
    if path.startswith("answers."):
        return row["answers"][path.split(".", 1)[1]]
    return row["probabilities"][path]


def load(path):
    out = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            out[(row["case_id"], row["event_index"])] = row
    return out


def stats(values):
    if not values:
        return None
    return {
        "n": len(values),
        "max": max(values),
        "p50": statistics.median(values),
        "mean": statistics.fmean(values),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--published", required=True)
    parser.add_argument("--replay", required=True)
    parser.add_argument("--out")
    args = parser.parse_args()

    pub, rep = load(args.published), load(args.replay)
    shared = sorted(set(pub) & set(rep))

    req_match = req_mismatch = 0
    deltas = {k: [] for k in PROB_KEYS + DERIVED}
    disp_flips, action_flips, detected_flips = [], [], []
    pub_disp, rep_disp = Counter(), Counter()

    for key in shared:
        p, r = pub[key], rep[key]
        if p["request_sha256"] == r["request_sha256"]:
            req_match += 1
        else:
            req_mismatch += 1
        for path in PROB_KEYS + DERIVED:
            deltas[path].append(abs(float(get(p, path)) - float(get(r, path))))
        pub_disp[p["answers"]["disposition"]] += 1
        rep_disp[r["answers"]["disposition"]] += 1
        if p["answers"]["disposition"] != r["answers"]["disposition"]:
            disp_flips.append({"case_id": key[0], "event_index": key[1],
                               "l40s": p["answers"]["disposition"],
                               "h200": r["answers"]["disposition"],
                               "l40s_probs": {k: get(p, k) for k in PROB_KEYS[:3]},
                               "h200_probs": {k: get(r, k) for k in PROB_KEYS[:3]}})
        if p["action"] != r["action"]:
            action_flips.append({"case_id": key[0], "event_index": key[1],
                                 "l40s": p["action"], "h200": r["action"]})
        if bool(p["detected"]) != bool(r["detected"]):
            detected_flips.append({"case_id": key[0], "event_index": key[1]})

    all_prob = [d for k in PROB_KEYS for d in deltas[k]]
    result = {
        "kind": "defenseclaw-system-one-cross-hardware-agreement",
        "arm": "open-jev-qwen-2b",
        "baseline_hardware": "4x NVIDIA L40S (sm_89)",
        "replay_hardware": "1x NVIDIA H200 (sm_90)",
        "attn_implementation": "sdpa (hardcoded in jev/model.py, no override)",
        "dtype": "bfloat16",
        "prefix_cache": False,
        "paired_rows": len(shared),
        "published_only": len(set(pub) - set(rep)),
        "replay_only": len(set(rep) - set(pub)),
        "request_sha256_match": req_match,
        "request_sha256_mismatch": req_mismatch,
        "per_scalar_abs_delta": {k: stats(v) for k, v in deltas.items()},
        "all_probability_scalars_abs_delta": stats(all_prob),
        "argmax_disposition_flips": len(disp_flips),
        "action_flips": len(action_flips),
        "detected_flips": len(detected_flips),
        "disposition_distribution_l40s": dict(pub_disp),
        "disposition_distribution_h200": dict(rep_disp),
        "flip_detail": disp_flips[:20],
        "action_flip_detail": action_flips[:20],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, sort_keys=True)
            handle.write("\n")


if __name__ == "__main__":
    main()
