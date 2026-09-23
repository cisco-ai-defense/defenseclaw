"""Build a smoke cases file whose C7/I3/Q2 expansion is exactly N prediction rows.

Cases expand to a variable number of Q2 decisions (one per event), so a row target
cannot be met by taking a fixed number of cases. This walks a deterministic shuffle of
the corpus and takes cases until the row count lands exactly on the target, preferring
whatever grade mix that produces rather than forcing one, so the smoke exercises the
same request shapes the full run will.
"""
import argparse
import collections
import json
import random

parser = argparse.ArgumentParser()
parser.add_argument("--requests", required=True, help="dumped request bodies (one per row)")
parser.add_argument("--cases", required=True)
parser.add_argument("--out", required=True)
parser.add_argument("--rows", type=int, default=33)
parser.add_argument("--seed", type=int, default=741983)
args = parser.parse_args()

rows_per_case = collections.Counter()
for line in open(args.requests, encoding="utf-8"):
    if line.strip():
        rows_per_case[str(json.loads(line)["case_id"])] += 1

cases = {}
for line in open(args.cases, encoding="utf-8"):
    if line.strip():
        row = json.loads(line)
        cases[str(row["id"])] = line

order = sorted(rows_per_case)
random.Random(args.seed).shuffle(order)

picked, total = [], 0
for case_id in order:
    count = rows_per_case[case_id]
    if total + count <= args.rows:
        picked.append(case_id)
        total += count
    if total == args.rows:
        break

if total != args.rows:
    raise SystemExit(f"could not hit {args.rows} rows exactly; got {total}")

with open(args.out, "w", encoding="utf-8") as handle:
    for case_id in picked:
        handle.write(cases[case_id])

print(json.dumps({"out": args.out, "cases": len(picked), "rows": total,
                  "rows_per_case": [rows_per_case[c] for c in picked]}, indent=2))
