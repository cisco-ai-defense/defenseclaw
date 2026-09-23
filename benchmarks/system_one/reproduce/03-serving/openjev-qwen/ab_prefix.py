"""Gate Open-Jev's opt-in prefix cache against the unmodified full-prefill path.

Open-Jev ships request-local prefix reuse but documents it as opt-in "pending
full-checkpoint BF16 validation". It is worth ~7x on our workload because all
seven candidate sequences of a Q2 decision share the same long context prefix.
This runs both paths over real s2 requests on the same loaded weights and
reports the worst-case divergence in candidate logits, in the temperature-scaled
probabilities the scorer actually consumes, and in the derived disposition.

Exit status is 0 only if no disposition flips and the probability divergence
stays under --tolerance, so a run script can use it as a hard gate.
"""
import argparse
import json
import sys
import time

sys.path.insert(0, "$WORK/sysone/Open-Jev")
from jev.api import compile_request, format_response  # noqa: E402
from jev.metrics import softmax  # noqa: E402
from jev.model import DecisionModel  # noqa: E402


def dispositions(records, rows, temperature):
    answers = format_response(records, [softmax(row, temperature) for row in rows])["answers"]
    return answers


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--requests", required=True)
    parser.add_argument("--limit", type=int, default=60)
    parser.add_argument("--device", default="cuda:0")
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--tolerance", type=float, default=2e-3)
    parser.add_argument("--out")
    args = parser.parse_args()

    import torch
    temperature = json.loads(open(args.checkpoint + "/temperature.json").read())["temperature"]
    model = DecisionModel.load(args.checkpoint, device=args.device)

    rows = [json.loads(line) for line in open(args.requests, encoding="utf-8")][: args.limit]
    worst_logit = worst_prob = 0.0
    flips = 0
    plain_seconds = cached_seconds = 0.0
    plain_tokens = cached_processed = 0
    details = []

    for row in rows:
        records = compile_request(row["state"], row["questions"])

        start = time.perf_counter()
        with torch.inference_mode():
            plain = [value.float().cpu().tolist() for value in model(records)]
        torch.cuda.synchronize()
        plain_seconds += time.perf_counter() - start
        plain_tokens += model.last_input_tokens

        start = time.perf_counter()
        cached_raw, stats = model.score_cached(records, batch_size=args.batch_size)
        cached = [value.float().cpu().tolist() for value in cached_raw]
        torch.cuda.synchronize()
        cached_seconds += time.perf_counter() - start
        cached_processed += stats["processed_input_tokens"]

        for left, right in zip(plain, cached):
            worst_logit = max(worst_logit, max(abs(a - b) for a, b in zip(left, right)))
            pl, pr = softmax(left, temperature), softmax(right, temperature)
            worst_prob = max(worst_prob, max(abs(a - b) for a, b in zip(pl, pr)))

        left_answers = dispositions(records, plain, temperature)
        right_answers = dispositions(records, cached, temperature)
        for key in left_answers:
            lv = left_answers[key].get("choice", left_answers[key].get("noul"))
            rv = right_answers[key].get("choice", right_answers[key].get("noul"))
            if lv != rv and not isinstance(lv, float):
                flips += 1
                details.append({"case_id": row["case_id"], "field": key, "plain": lv, "cached": rv})

    result = {
        "requests": len(rows),
        "worst_abs_logit_delta": worst_logit,
        "worst_abs_probability_delta": worst_prob,
        "categorical_answer_flips": flips,
        "flip_details": details[:20],
        "tolerance": args.tolerance,
        "passed": flips == 0 and worst_prob <= args.tolerance,
        "timing": {
            "plain_seconds": round(plain_seconds, 2),
            "cached_seconds": round(cached_seconds, 2),
            "speedup": round(plain_seconds / cached_seconds, 3) if cached_seconds else None,
            "plain_seconds_per_request": round(plain_seconds / len(rows), 4),
            "cached_seconds_per_request": round(cached_seconds / len(rows), 4),
        },
        "tokens": {
            "logical_input_tokens": plain_tokens,
            "cached_processed_input_tokens": cached_processed,
            "prefill_reduction": round(1 - cached_processed / plain_tokens, 4) if plain_tokens else None,
        },
    }
    print(json.dumps(result, indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, sort_keys=True)
            handle.write("\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
