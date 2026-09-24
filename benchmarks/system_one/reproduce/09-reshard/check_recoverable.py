"""READ-ONLY: is a cap-tripped prediction body recoverable with --resume --resume-retry-errors?

That path calls validate_resume_prefix(retry_errors=True), which walks the file from row 1
and only starts DROPPING at the first row carrying error_code. But before it may drop a row
it still has to pass that row through:
  - the run_id/model check
  - the ordered plan identity check
  - the prediction schema
  - a request_sha256 recomputed from the rebuilt canonical request
If an error row fails any of those, resume RAISES instead of dropping, and this recovery
path does not exist. So the question is whether the error rows are themselves well-formed.

Touches nothing: opens the body read-only and writes no files.
"""
import hashlib, json, sys
from pathlib import Path

R = Path("/teamspace/studios/this_studio/sysone")
sys.path.insert(0, str(R))
import benchmark_run_system_one as B
from jsonschema import Draft202012Validator

AGREE = R / "agree"
body = Path(sys.argv[1])
model = sys.argv[2]
run_id = sys.argv[3]

schema = json.loads((AGREE / "cfg/system-one-prediction-v1.schema.json").read_text())
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema)

first_error = None
rows = errs = 0
schema_fails = []
missing_hash = 0
codes = {}
for i, line in enumerate(open(body, encoding="utf-8")):
    line = line.strip()
    if not line:
        continue
    r = json.loads(line)
    rows += 1
    bad = r.get("error_code") or r.get("route") == "error"
    if bad:
        errs += 1
        codes[r.get("error_code", "?")] = codes.get(r.get("error_code", "?"), 0) + 1
        if first_error is None:
            first_error = i
        if not r.get("request_sha256"):
            missing_hash += 1
        err = next(validator.iter_errors(r), None)
        if err is not None and len(schema_fails) < 5:
            loc = ".".join(str(p) for p in err.absolute_path) or "root"
            schema_fails.append({"row0": i, "at": loc, "validator": err.validator})
    if r.get("run_id") != run_id or r.get("model") != model:
        print(json.dumps({"FATAL": "run_id/model mismatch", "row0": i,
                          "run_id": r.get("run_id"), "model": r.get("model")}))
        break

print(json.dumps({
    "body": str(body), "rows": rows, "error_rows": errs, "error_codes": codes,
    "first_error_row0": first_error,
    "clean_prefix_rows": first_error if first_error is not None else rows,
    "error_rows_failing_schema": len(schema_fails), "schema_fail_examples": schema_fails,
    "error_rows_missing_request_sha256": missing_hash,
    "meta_exists": (Path(str(body) + ".meta.json")).exists(),
}, indent=2))

# Spot-check that an error row's request_sha256 still equals the rebuilt canonical request,
# by rebuilding just the cases around the trip point from a temporary in-memory slice.
if first_error is not None:
    idx = json.load(open(R / "reshard/case_index.json"))
    cum = idx["cum"]
    import bisect
    k = bisect.bisect_right(cum, first_error) - 1
    a, b = k, min(k + 30, len(idx["ids"]))
    tmp = R / "reshard/_recov_slice.jsonl"
    with open(AGREE / "s3-cases.jsonl", "rb") as src, open(tmp, "wb") as out:
        for i, line in enumerate(src):
            if i >= b: break
            if i >= a: out.write(line)
    ctx = B.load_json(AGREE / "cfg/contexts-v1.json")
    qcfg = B.load_json(AGREE / "cfg/questions-v1.json")
    prod = (tmp, ["C7"], ["I3"], ["Q2"], ctx, qcfg, "structured")
    want = {}
    for n, (cid, job) in enumerate(B.iter_jobs(*prod)):
        want[cum[a] + n] = (cid, job[0],
                            hashlib.sha256(B.canonical_request(model, job[4], job[6]).encode()).hexdigest())
    checked = mism = 0
    for i, line in enumerate(open(body, encoding="utf-8")):
        if i not in want: continue
        r = json.loads(line)
        cid, ev, dig = want[i]
        checked += 1
        if (r["case_id"], int(r["event_index"])) != (cid, ev) or r.get("request_sha256") != dig:
            mism += 1
    tmp.unlink(missing_ok=True)
    print(json.dumps({"spot_checked_rows_around_trip": checked, "mismatches": mism,
                      "case_range": [a, b]}, indent=2))
