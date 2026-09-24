"""Merge the nimble s3 arm: live shard0 prefix + card-3 chunk shards -> one artifact.

Verification performed BEFORE anything is written:
  1. The set of completed chunks is exactly contiguous {c_min..cmax}, so the chunk shards
     cover cases [boundary_case, 24476) with no gap.
  2. shard0 is validated with the runner's OWN validate_resume_prefix() against the full
     s3-cases.jsonl plan: every row must match the ordered plan identity, satisfy the
     prediction schema, and carry a request_sha256 equal to the rebuilt canonical request.
  3. Every chunk shard is validated the same way against its own slice plan, and its
     meta must say complete:true with prediction_sha256 equal to its on-disk digest.
  4. The assembled row sequence is compared position-by-position against the globally
     recomputed (case_id, event_index) plan, all 100,001 of them, and every pair must be
     distinct. That is coverage, order and de-duplication in one pass.
  5. The merged digest is computed from the bytes on disk and re-read afterwards.

Row serialisation matches the programme's other settled artifacts (settle_arm.py):
json.dumps(row, sort_keys=True, ensure_ascii=False), i.e. default separators.
"""
import argparse, hashlib, json, sys
from pathlib import Path

R = Path("/teamspace/studios/this_studio/sysone")
sys.path.insert(0, str(R))
import benchmark_run_system_one as B
from jsonschema import Draft202012Validator

AGREE = R / "agree"
CASES = AGREE / "s3-cases.jsonl"
RUNDIR = R / "runs/nimble-s3"
RS = R / "reshard"
ARM = "bespoke-nimble-9b"
RUN_ID = "s3-bespoke-nimble-9b-h200"
REV = "93ec5d6ff1a9cd31d6cc0e0c58d312465d36de7c"
SHARD0 = RUNDIR / f"{ARM}-shard0.jsonl"


def sha256_file(path):
    d = hashlib.sha256()
    with open(path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            d.update(blk)
    return d.hexdigest()


def die(msg):
    sys.exit(f"ABORT: {msg}")


ap = argparse.ArgumentParser()
ap.add_argument("--write", action="store_true", help="write the artifact (default: verify only)")
args = ap.parse_args()

table = json.load(open(RS / "chunks.json"))
chunks = table["chunks"]
cmax = table["cmax"]
idx = json.load(open(RS / "case_index.json"))
ids, counts, cum = idx["ids"], idx["counts"], idx["cum"]

# ---- 1. which chunks completed, and is the tail contiguous? ----
ok, bad = [], []
for p in sorted((RS / "done").glob("*.json")):
    rec = json.loads(p.read_text())
    (ok if rec.get("status") == "ok" else bad).append(rec)
ok_chunks = sorted(r["chunk"] for r in ok)
if not ok_chunks:
    die("no completed chunks")
c_min = ok_chunks[0]
expected = list(range(c_min, cmax + 1))
if ok_chunks != expected:
    die(f"completed chunks are not contiguous to the end: missing {sorted(set(expected) - set(ok_chunks))}"
        f" / unexpected {sorted(set(ok_chunks) - set(expected))}")
if bad:
    print(f"NOTE: {len(bad)} non-ok chunk record(s): {[(r['chunk'], r.get('status')) for r in bad]}")

boundary_case = chunks[c_min]["case_start"]
boundary_req = cum[boundary_case]
print(json.dumps({"completed_chunks": [c_min, cmax], "n_chunk_shards": len(ok_chunks),
                  "boundary_case_index": boundary_case,
                  "shard0_keeps_requests": boundary_req,
                  "chunk_shards_cover_requests": 100001 - boundary_req}, indent=2))

ctx = B.load_json(AGREE / "cfg/contexts-v1.json")
qcfg = B.load_json(AGREE / "cfg/questions-v1.json")
schema = json.loads((AGREE / "cfg/system-one-prediction-v1.schema.json").read_text())
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema)


def rows_of(path):
    n = 0
    with open(path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 22), b""):
            n += blk.count(b"\n")
    return n


# ---- 2. validate shard0 against the FULL plan using the runner's own checker ----
s0_rows = rows_of(SHARD0)
if s0_rows < boundary_req:
    die(f"shard0 has {s0_rows} rows but must cover {boundary_req} to meet the chunk pool")
full_producer = (CASES, ["C7"], ["I3"], ["Q2"], ctx, qcfg, "structured")
validated, keep, s0_tokens_all = B.validate_resume_prefix(
    SHARD0, B.iter_jobs(*full_producer), RUN_ID, ARM, 100001, validator, False)
if validated != s0_rows:
    die(f"shard0 validated {validated} of {s0_rows} rows")
print(f"shard0: validate_resume_prefix OK for all {validated} rows "
      f"(keeping first {boundary_req}, discarding {s0_rows - boundary_req} overshoot rows)")

# ---- 3. validate each chunk shard against its own slice plan ----
shard_info = []
for c in expected:
    ch = chunks[c]
    n = ch["shard"]
    pred = RUNDIR / f"{ARM}-shard{n}.jsonl"
    meta_p = Path(str(pred) + ".meta.json")
    slice_p = RUNDIR / f"cases-shard{n}.jsonl"
    for p in (pred, meta_p, slice_p):
        if not p.exists():
            die(f"missing {p}")
    meta = json.loads(meta_p.read_text())
    if meta.get("complete") is not True:
        die(f"shard{n} meta complete is not true")
    disk = sha256_file(pred)
    if meta["prediction_sha256"] != disk:
        die(f"shard{n} meta prediction_sha256 {meta['prediction_sha256']} != on-disk {disk}")
    if meta["requests"] != ch["requests"]:
        die(f"shard{n} meta requests {meta['requests']} != chunk requests {ch['requests']}")
    if meta["model_revision"] != REV or meta["model"] != ARM:
        die(f"shard{n} model/revision mismatch: {meta['model']} {meta['model_revision']}")
    if (meta["contexts"], meta["instructions"], meta["questions"], meta["instruction_format"]) != \
       (["C7"], ["I3"], ["Q2"], "structured"):
        die(f"shard{n} grid mismatch: {meta['contexts']} {meta['instructions']} "
            f"{meta['questions']} {meta['instruction_format']}")
    sp = (slice_p, ["C7"], ["I3"], ["Q2"], ctx, qcfg, "structured")
    v, _, _ = B.validate_resume_prefix(
        pred, B.iter_jobs(*sp), f"{RUN_ID}-shard{n}", ARM, ch["requests"], validator, False)
    if v != ch["requests"]:
        die(f"shard{n} validated {v} of {ch['requests']} rows")
    shard_info.append({"chunk": c, "shard": n, "path": pred, "meta": meta,
                       "requests": ch["requests"], "case_start": ch["case_start"],
                       "case_end": ch["case_end"], "sha256": disk})
    print(f"shard{n}: chunk {c} cases[{ch['case_start']}..{ch['case_end']}) "
          f"{ch['requests']} rows validated, digest OK")

# ---- 4/5. assemble in plan order and verify coverage ----
plan = []
for cid, k in zip(ids, counts):
    for e in range(k):
        plan.append((cid, e))
if len(plan) != 100001:
    die(f"global plan is {len(plan)} requests")

outdir = RUNDIR / "settled"
merged = outdir / f"{ARM}.jsonl"
if not args.write:
    print("verify-only mode: all pre-write checks passed; re-run with --write to emit the artifact")
    sys.exit(0)
outdir.mkdir(parents=True, exist_ok=True)

# chunk ascending == case ascending == shard number descending
ordered = [(SHARD0, boundary_req)] + [(s["path"], s["requests"]) for s in shard_info]
pos = 0
seen = set()
tok = calls = 0
with open(merged, "w", encoding="utf-8") as out:
    for path, take in ordered:
        n = 0
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if n >= take:
                    break
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                key = (row["case_id"], int(row["event_index"]))
                if key != plan[pos]:
                    die(f"row {pos} is {key}, plan expects {plan[pos]} (source {path.name})")
                if key in seen:
                    die(f"duplicate (case_id, event_index) {key} at row {pos}")
                seen.add(key)
                tok += int(row.get("input_tokens", 0))
                calls += 1
                row["run_id"] = RUN_ID
                out.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
                pos += 1
                n += 1
        if n != take:
            die(f"{path.name} yielded {n} rows, expected {take}")
if pos != 100001:
    die(f"merged {pos} rows, expected 100001")
if len(seen) != 100001:
    die(f"{len(seen)} distinct pairs, expected 100001")
cases_seen = len({c for c, _ in seen})
if cases_seen != 24476:
    die(f"{cases_seen} distinct cases, expected 24476")

digest = sha256_file(merged)
meta = {
    "schema_version": "1",
    "run_id": RUN_ID,
    "stage": "s3",
    "model": ARM,
    "model_revision": REV,
    "cases": cases_seen,
    "cases_sha256": sha256_file(CASES),
    "requests": pos,
    "complete": True,
    "prediction_sha256": digest,
    "contexts": ["C7"],
    "instructions": ["I3"],
    "questions": ["Q2"],
    "instruction_format": "structured",
    "actual_input_tokens": tok,
    "attempted_provider_calls": calls,
    "reserved_input_tokens": sum(s["meta"]["reserved_input_tokens"] for s in shard_info),
    "estimated_usd": 0.0,
    "serving": {
        "attn_implementation": "sdpa (hardcoded in nimble_shim.py, unchanged)",
        "max_length": 8192,
        "concurrency_per_driver": 4,
        "timeout_s": 600,
        "replicas": "shard0 on card 2 port 8833 (pre-existing server, untouched); "
                    "chunk shards on card 3, one replica process per port",
    },
    "merge": {
        "shards": 1 + len(shard_info),
        "row_order": "global plan order (cases in s3-cases.jsonl order, event_index ascending)",
        "shard0": {
            "run_id": RUN_ID,
            "rows_on_disk": s0_rows,
            "rows_used": boundary_req,
            "overshoot_rows_discarded": s0_rows - boundary_req,
            "covers_cases": [0, boundary_case],
            "prediction_sha256_full_file": sha256_file(SHARD0),
            "note": "live driver pid 92139, stopped at a case boundary it had passed; the "
                    "first rows_used rows are a validated prefix of the full plan, and the "
                    "discarded overshoot rows are covered by the chunk shards instead",
        },
        "chunk_shards": [
            {"shard": s["shard"], "chunk": s["chunk"], "run_id": s["meta"]["run_id"],
             "cases": [s["case_start"], s["case_end"]], "requests": s["requests"],
             "prediction_sha256": s["sha256"]}
            for s in shard_info
        ],
        "actual_input_tokens_note": "summed from per-row input_tokens across the merged rows",
    },
}
meta_p = Path(str(merged) + ".meta.json")
meta_p.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")

reread = sha256_file(merged)
declared = json.loads(meta_p.read_text())["prediction_sha256"]
if reread != declared:
    die(f"on-disk digest {reread} != declared {declared}")
print(json.dumps({"merged": str(merged), "rows": pos, "cases": cases_seen,
                  "prediction_sha256": digest,
                  "digest_reverified_from_disk": reread == declared,
                  "bytes": merged.stat().st_size}, indent=2))
print("=== MERGE OK ===")
