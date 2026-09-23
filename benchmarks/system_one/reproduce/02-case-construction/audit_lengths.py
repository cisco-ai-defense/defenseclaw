"""Audit real s2 prompt lengths against each model's hard input ceiling.

Both families reject rather than truncate, so any prompt over the ceiling becomes
an `error` decision rather than a silently degraded one. This measures how many
of the 30,310 Q2 decisions would overflow, for Open-Jev's 4,096-token
per-candidate limit and for Nimble's trained 2,048 / served 8,192 budgets.
"""
import argparse
import json
import sys

sys.path.insert(0, "$WORK/sysone/Open-Jev")


def percentile(values, q):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, int(q * len(ordered)) - 1))]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", required=True)
    parser.add_argument("--family", choices=["openjev", "nimble"], required=True)
    parser.add_argument("--tokenizer", required=True)
    parser.add_argument("--revision")
    parser.add_argument("--limits", default="2048,4096,8192")
    parser.add_argument("--out")
    args = parser.parse_args()

    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(args.tokenizer, revision=args.revision)

    rows = [json.loads(line) for line in open(args.requests, encoding="utf-8")]
    lengths = []

    if args.family == "openjev":
        from jev.api import candidate_prompts, compile_request
        for row in rows:
            longest = 0
            for record in compile_request(row["state"], row["questions"]):
                for prompt in candidate_prompts(record):
                    text = tokenizer.apply_chat_template(
                        [{"role": "user", "content": prompt}], tokenize=False,
                        add_generation_prompt=True, enable_thinking=False)
                    longest = max(longest, len(tokenizer.encode(text, add_special_tokens=False)))
            lengths.append(longest)
    else:
        sys.path.insert(0, "/opt/dlami/nvme/checkpoints/nimble-9b")
        from parallel_schema import prepare_prompts
        sys.path.insert(0, "$WORK/sysone")
        from nimble_shim import build_schema, serialize
        for row in rows:
            schema = build_schema(row["questions"])
            # prepare_prompts raises past the ceiling, so probe with a generous budget.
            prepared = prepare_prompts(tokenizer, serialize(row["state"]), schema, 10 ** 6)
            lengths.append(max(len(ids) for ids in prepared.full_ids))

    limits = [int(value) for value in args.limits.split(",")]
    result = {
        "family": args.family, "decisions": len(lengths),
        "max_prompt_tokens": max(lengths), "mean": round(sum(lengths) / len(lengths), 1),
        "p50": percentile(lengths, 0.50), "p95": percentile(lengths, 0.95),
        "p99": percentile(lengths, 0.99), "p999": percentile(lengths, 0.999),
        "overflow": {str(limit): sum(1 for value in lengths if value > limit) for limit in limits},
        "overflow_rate": {str(limit): round(sum(1 for value in lengths if value > limit) / len(lengths), 6)
                          for limit in limits},
    }
    print(json.dumps(result, indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, sort_keys=True)
            handle.write("\n")


if __name__ == "__main__":
    main()
