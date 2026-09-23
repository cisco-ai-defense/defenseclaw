"""Dump genuine s2 request bodies using the benchmark runner's own state builder.

Guarantees the prefix-cache A/B and the token-length audit see byte-identical
`state` and `questions` to what the real run will send.
"""
import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, "$WORK/defenseclaw-system-one/benchmarks/scripts")
from benchmark_run_system_one import canonical_request, iter_jobs, load_json  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--limit", type=int, default=0, help="0 = all")
    parser.add_argument("--sample", type=int, default=0, help="reservoir sample size")
    parser.add_argument("--seed", type=int, default=741983)
    parser.add_argument("--repo", default="$WORK/defenseclaw-system-one")
    args = parser.parse_args()

    repo = Path(args.repo)
    contexts = load_json(repo / "benchmarks/system_one/contexts-v1.json")
    questions = load_json(repo / "benchmarks/system_one/questions-v1.json")

    rows = []
    rng = random.Random(args.seed)
    seen = 0
    for case_id, job in iter_jobs(Path(args.cases), ["C7"], ["I3"], ["Q2"], contexts, questions, "structured"):
        event_index, context_id, instruction_id, question_id, state, state_meta, question_set = job
        row = {
            "case_id": case_id, "event_index": event_index,
            "state": state, "questions": question_set,
            "context_bytes": state_meta["bytes"],
            "canonical_len": len(canonical_request("m", state, question_set).encode()),
        }
        seen += 1
        if args.sample:
            if len(rows) < args.sample:
                rows.append(row)
            else:
                index = rng.randrange(seen)
                if index < args.sample:
                    rows[index] = row
        else:
            rows.append(row)
            if args.limit and len(rows) >= args.limit:
                break

    with open(args.out, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(json.dumps({"written": len(rows), "scanned": seen, "out": args.out}))


if __name__ == "__main__":
    main()
