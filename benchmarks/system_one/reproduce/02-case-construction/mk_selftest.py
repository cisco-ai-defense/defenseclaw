"""Pick selftest requests: the longest real prompts (worst-case memory) plus a
deterministic random sample (representative latency). Longest-first, so an OOM shows
up on request 1 rather than halfway through a rate measurement."""
import argparse
import json
import random

parser = argparse.ArgumentParser()
parser.add_argument("--requests", required=True)
parser.add_argument("--out", required=True)
parser.add_argument("--longest", type=int, default=3)
parser.add_argument("--sample", type=int, default=9)
parser.add_argument("--seed", type=int, default=741983)
args = parser.parse_args()

rows = [json.loads(line) for line in open(args.requests, encoding="utf-8") if line.strip()]
order = sorted(range(len(rows)), key=lambda i: -rows[i]["canonical_len"])
picked = order[:args.longest]
rest = [i for i in order[args.longest:]]
picked += random.Random(args.seed).sample(rest, args.sample)

with open(args.out, "w", encoding="utf-8") as handle:
    for index in picked:
        handle.write(json.dumps(rows[index], ensure_ascii=False) + "\n")

print(json.dumps({
    "written": len(picked), "out": args.out,
    "canonical_len_of_picked": [rows[i]["canonical_len"] for i in picked],
    "corpus_max_canonical_len": rows[order[0]]["canonical_len"],
}, indent=2))
