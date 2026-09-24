"""Prove that splitting the cases file does not change a single request body.

Takes a case range that the live shard0 has ALREADY completed, builds the slice the
way next_chunk.py does, re-derives every request from the slice using the runner's own
iter_jobs()/canonical_request(), and compares case_id, event_index and the sha256 of
the canonical wire body against the rows shard0 actually sent.

If these match, a slice run sends byte-identical bytes to the server, so the only thing
that could differ between shard0's rows and a new shard's rows is the server's own
nondeterminism -- not the request. Serving conditions are pinned separately.
"""
import hashlib, json, sys
from pathlib import Path

R = Path("/teamspace/studios/this_studio/sysone")
sys.path.insert(0, str(R))
import benchmark_run_system_one as B

AGREE = R / "agree"
CASES = AGREE / "s3-cases.jsonl"
SHARD0 = R / "runs/nimble-s3/bespoke-nimble-9b-shard0.jsonl"
MODEL = "bespoke-nimble-9b"

a, b = int(sys.argv[1]), int(sys.argv[2])
idx = json.load(open(R / "reshard/case_index.json"))
cum = idx["cum"]
req_a, req_b = cum[a], cum[b]

tmp = R / "reshard/_verify_slice.jsonl"
with open(CASES, "rb") as src, open(tmp, "wb") as out:
    for i, line in enumerate(src):
        if i >= b:
            break
        if i >= a:
            out.write(line)

ctx = B.load_json(AGREE / "cfg/contexts-v1.json")
qcfg = B.load_json(AGREE / "cfg/questions-v1.json")
producer = (tmp, ["C7"], ["I3"], ["Q2"], ctx, qcfg, "structured")

cases_n, requests_n, _ = B.plan_counts(*producer)
expect_requests = req_b - req_a
print(json.dumps({"case_range": [a, b], "slice_cases": cases_n,
                  "slice_requests": requests_n,
                  "global_request_range": [req_a, req_b],
                  "slice_requests_match_global_span": requests_n == expect_requests}))
if requests_n != expect_requests:
    sys.exit("ABORT: slice request count does not match the global plan span")

# shard0 rows for that global range
rows = []
with open(SHARD0, encoding="utf-8") as fh:
    for i, line in enumerate(fh):
        if i >= req_b:
            break
        if i >= req_a:
            rows.append(json.loads(line))
if len(rows) != expect_requests:
    sys.exit(f"ABORT: shard0 only has {len(rows)} of {expect_requests} rows in that range yet")

bad = []
for n, ((case_id, job), row) in enumerate(zip(B.iter_jobs(*producer), rows)):
    ev, cid_, iid, qid, state, meta, questions = job
    canonical = B.canonical_request(MODEL, state, questions)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    if (case_id, ev) != (row["case_id"], row["event_index"]):
        bad.append({"n": n, "why": "identity", "slice": [case_id, ev],
                    "shard0": [row["case_id"], row["event_index"]]})
    elif digest != row["request_sha256"]:
        bad.append({"n": n, "why": "request_sha256", "case_id": case_id, "event_index": ev,
                    "slice": digest, "shard0": row["request_sha256"]})
    elif meta["sha256"] != row["context_sha256"]:
        bad.append({"n": n, "why": "context_sha256", "case_id": case_id, "event_index": ev})
    if len(bad) > 5:
        break
print(json.dumps({"compared": len(rows), "mismatches": len(bad), "examples": bad[:5]}, indent=2))
tmp.unlink(missing_ok=True)
sys.exit(1 if bad else 0)
