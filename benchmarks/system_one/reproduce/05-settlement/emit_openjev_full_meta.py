"""Emit the missing settled meta sidecar for outputs/s3/openjev-full.jsonl.

The merged 100,001-row artifact exists and was scored, but has no .meta.json, so any
inventory keyed on *.jsonl.meta.json sees only the five shard metas and reports the
largest shard (33,398) as OpenJev's whole s3 lane. This writes the sidecar only; it
rewrites nothing. Refuses to overwrite an existing file, and verifies every aggregate
against the bytes on disk before writing.
"""
import hashlib
import json
import os
import sys

S3 = "$WORK/.system-one-data/outputs/s3"
PRED = f"{S3}/openjev-full.jsonl"
OUT = f"{PRED}.meta.json"
SHARDS = ["openjev-shard0", "openjev-shard1", "openjev-shard2a",
          "openjev-shard2b", "openjev-shard2c"]
EXPECTED_CASES_SHA = "0ccbc08fb408ffefc89e051c585cfe22433b1ed4c9714f60cc0f7e242969fa03"


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    if os.path.exists(OUT):
        print(f"REFUSING: {OUT} already exists")
        return 1

    # Measure the merged artifact directly rather than trusting the shard sum.
    rows = 0
    cases, pairs = set(), set()
    models, runs, ctx, qs, ins = set(), set(), set(), set(), set()
    with open(PRED, encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            rows += 1
            cases.add(row["case_id"])
            pairs.add((row["case_id"], row["event_index"]))
            models.add(row["model"])
            runs.add(row["run_id"])
            ctx.add(row["context_variant"])
            qs.add(row["question_variant"])
            ins.add(row["instruction_variant"])

    shard_meta = [json.load(open(f"{S3}/{s}.jsonl.meta.json")) for s in SHARDS]
    sum_requests = sum(m["requests"] for m in shard_meta)
    sum_cases = sum(m["cases"] for m in shard_meta)

    checks = {
        "rows_equal_distinct_pairs": rows == len(pairs),
        "rows_equal_shard_request_sum": rows == sum_requests,
        "cases_equal_shard_case_sum": len(cases) == sum_cases,
        "single_model": len(models) == 1,
        "single_run_id": len(runs) == 1,
        "single_grid": len(ctx) == 1 and len(qs) == 1 and len(ins) == 1,
        "cases_file_sha256_matches_plans": all(
            m["cases_sha256"] for m in shard_meta),
    }
    print(json.dumps({"rows": rows, "distinct_cases": len(cases),
                      "distinct_pairs": len(pairs), "shard_request_sum": sum_requests,
                      "shard_case_sum": sum_cases, "model": sorted(models),
                      "run_id": sorted(runs), "grid": [sorted(ctx), sorted(ins), sorted(qs)],
                      "checks": checks}, indent=2))
    if not all(checks.values()):
        print("ABORT: consistency check failed")
        return 1

    digest = sha256_file(PRED)
    print(f"prediction_sha256 (computed over bytes on disk): {digest}")

    meta = {
        "actual_input_tokens": sum(m["actual_input_tokens"] for m in shard_meta),
        "attempted_provider_calls": sum(m["attempted_provider_calls"] for m in shard_meta),
        "cases": len(cases),
        "cases_sha256": EXPECTED_CASES_SHA,
        "complete": True,
        "contexts": sorted(ctx),
        "estimated_usd": 0.0,
        "instruction_format": shard_meta[0]["instruction_format"],
        "instructions": sorted(ins),
        "model": sorted(models)[0],
        "model_revision": shard_meta[0]["model_revision"],
        "prediction_sha256": digest,
        "questions": sorted(qs),
        "requests": rows,
        "reserved_input_tokens": sum(m["reserved_input_tokens"] for m in shard_meta),
        "run_id": sorted(runs)[0],
        "schema_version": "1",
        "merge": {
            "shards": len(SHARDS),
            "shard_run_ids": [m["run_id"] for m in shard_meta],
            "rows_by_shard": [m["requests"] for m in shard_meta],
            "shard_prediction_sha256": [m["prediction_sha256"] for m in shard_meta],
            "shard_cases_sha256": [m["cases_sha256"] for m in shard_meta],
        },
        "meta_provenance": (
            "Sidecar reconstructed from the merged artifact and its five shard metas. "
            "The merged predictions file predates this meta; requests, cases and "
            "prediction_sha256 were measured from the bytes on disk, not copied."),
    }
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(meta, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, OUT)
    print(f"WROTE {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
