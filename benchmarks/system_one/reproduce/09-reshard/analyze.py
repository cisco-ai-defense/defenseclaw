"""Confirm how s3-cases.jsonl expands and how the live driver orders requests."""
import json, sys, hashlib
from pathlib import Path

AGREE = Path("/teamspace/studios/this_studio/sysone/agree")
CASES = AGREE / "s3-cases.jsonl"
SHARD0 = Path("/teamspace/studios/this_studio/sysone/runs/nimble-s3/bespoke-nimble-9b-shard0.jsonl")

# Replicate case_jobs() event expansion exactly:
#   payload = case["payload"] if dict else {}
#   events  = payload["events"] if isinstance(list) else [payload]
# one job per (event, context, instruction, question); grid is 1x1x1 -> one job per event.
ids, counts = [], []
dup_ids = {}
seen = set()
empty_payload = 0
no_events_list = 0
for lineno, line in enumerate(open(CASES, encoding="utf-8"), 1):
    line = line.strip()
    if not line:
        continue
    case = json.loads(line)
    cid = str(case["id"])
    if cid in seen:
        dup_ids[cid] = dup_ids.get(cid, 1) + 1
    seen.add(cid)
    payload = case.get("payload") if isinstance(case.get("payload"), dict) else {}
    if not isinstance(case.get("payload"), dict):
        empty_payload += 1
    ev = payload.get("events")
    if isinstance(ev, list):
        n = len(ev)
    else:
        n = 1
        no_events_list += 1
    ids.append(cid)
    counts.append(n)

total = sum(counts)
print(json.dumps({
    "cases_lines": len(ids),
    "total_requests_computed": total,
    "matches_100001": total == 100001,
    "distinct_case_ids": len(seen),
    "duplicate_case_ids": len(dup_ids),
    "duplicate_examples": list(dup_ids.items())[:5],
    "cases_with_non_dict_payload": empty_payload,
    "cases_without_events_list_counted_as_1": no_events_list,
    "cases_with_zero_events": sum(1 for c in counts if c == 0),
    "min_events": min(counts), "max_events": max(counts),
}, indent=2))

# cumulative request offset at each case boundary: cum[k] = requests produced by cases[0:k]
cum = [0]
for c in counts:
    cum.append(cum[-1] + c)

# --- Confirm the live driver's ordering against the on-disk prefix ---
# Plan order asserted by iter_jobs(): cases in file order, event_index ascending within case.
plan = []
for cid, n in zip(ids, counts):
    for e in range(n):
        plan.append((cid, e))
assert len(plan) == total

mismatch = None
rows = 0
pair_seen = set()
pair_dups = 0
with open(SHARD0, encoding="utf-8") as fh:
    for i, line in enumerate(fh):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        key = (r["case_id"], r["event_index"])
        if key in pair_seen:
            pair_dups += 1
        pair_seen.add(key)
        if i < len(plan) and (r["case_id"], int(r["event_index"])) != plan[i]:
            if mismatch is None:
                mismatch = {"row_index_0based": i, "on_disk": [r["case_id"], r["event_index"]],
                            "plan_expected": list(plan[i])}
        rows += 1
print(json.dumps({
    "shard0_rows": rows,
    "shard0_order_matches_plan_prefix": mismatch is None,
    "first_order_mismatch": mismatch,
    "shard0_duplicate_case_event_pairs": pair_dups,
    "shard0_distinct_pairs": len(pair_seen),
}, indent=2))

# Where is shard0 relative to case boundaries?
import bisect
k = bisect.bisect_right(cum, rows) - 1
print(json.dumps({
    "rows": rows,
    "largest_case_boundary_at_or_below_rows": k,
    "requests_through_case_boundary_k": cum[k],
    "rows_into_case_k": rows - cum[k],
    "case_k_id": ids[k] if k < len(ids) else None,
    "case_k_events": counts[k] if k < len(counts) else None,
}, indent=2))

json.dump({"ids": ids, "counts": counts, "cum": cum},
          open("/teamspace/studios/this_studio/sysone/reshard/case_index.json", "w"))
print("wrote case_index.json")
