"""Independent audit of the settled artifact, re-derived from the cases file."""
import hashlib, json
from pathlib import Path

R = Path("/teamspace/studios/this_studio/sysone")
S = R / "runs/nimble-s3/settled"
body = S / "bespoke-nimble-9b.jsonl"
idx = json.load(open(R / "reshard/case_index.json"))
ids, counts = idx["ids"], idx["counts"]

plan = []
for cid, k in zip(ids, counts):
    for e in range(k):
        plan.append((cid, e))

rows = err = 0
pairs = set()
runids, models, revs, ctx, ins, qs = set(), set(), set(), set(), set(), set()
order_ok = True
first_bad = None
toks = 0
for i, line in enumerate(open(body, encoding="utf-8")):
    line = line.strip()
    if not line:
        continue
    r = json.loads(line)
    rows += 1
    key = (r["case_id"], int(r["event_index"]))
    pairs.add(key)
    if i < len(plan) and key != plan[i]:
        order_ok = False
        if first_bad is None:
            first_bad = {"row": i, "got": key, "want": plan[i]}
    if r.get("error_code") or r.get("route") == "error":
        err += 1
    runids.add(r["run_id"]); models.add(r["model"]); revs.add(r["model_revision"])
    ctx.add(r["context_variant"]); ins.add(r["instruction_variant"]); qs.add(r["question_variant"])
    toks += int(r.get("input_tokens", 0))

d = hashlib.sha256()
with open(body, "rb") as fh:
    for b in iter(lambda: fh.read(1 << 20), b""):
        d.update(b)
meta = json.loads((Path(str(body) + ".meta.json")).read_text())

print(json.dumps({
    "rows": rows,
    "rows_equals_100001": rows == 100001,
    "distinct_case_event_pairs": len(pairs),
    "no_duplicate_pairs": len(pairs) == rows,
    "distinct_cases": len({c for c, _ in pairs}),
    "row_order_matches_recomputed_plan": order_ok,
    "first_order_mismatch": first_bad,
    "error_rows": err,
    "single_run_id": sorted(runids),
    "single_model": sorted(models),
    "single_revision": sorted(revs),
    "grid": [sorted(ctx), sorted(ins), sorted(qs)],
    "summed_input_tokens": toks,
    "exceeds_single_driver_200M_cap_by": toks - 200_000_000,
    "on_disk_sha256": d.hexdigest(),
    "meta_prediction_sha256": meta["prediction_sha256"],
    "digest_match": d.hexdigest() == meta["prediction_sha256"],
    "meta_complete": meta["complete"],
}, indent=1))
