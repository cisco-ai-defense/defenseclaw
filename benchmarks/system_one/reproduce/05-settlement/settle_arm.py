"""Merge an arm's stride shards, settle it, and emit the publishable artifact set.

Produces, for one arm:
  <arm>.jsonl                      merged predictions, shard order 0..N-1
  <arm>.jsonl.meta.json            settled meta, complete:true, prediction_sha256 over bytes
  <arm>.serving.json               serving freeze incl. host, card, resolved versions
  auc-variants-<arm>.json          four ranking variables (tie-corrected Mann-Whitney)
  mapping-check-<arm>.json
  recall-by-variable-<arm>.json    by_variable shape, includes the 0.00384502 cap
  scores/<run-id>.json             scorecard

Integrity is asserted before anything is written: row count equals the shard request sum,
every (case_id, event_index) pair is unique, exactly one model/grid, and the merged digest
is computed from the bytes on disk rather than carried over from the shards.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def run(cmd, label):
    print(f"--- {label} ---", flush=True)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout[-3000:])
        print(proc.stderr[-3000:], file=sys.stderr)
        raise SystemExit(f"ABORT: {label} failed rc={proc.returncode}")
    return proc.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True)
    ap.add_argument("--rundir", required=True)
    ap.add_argument("--cases", required=True)
    ap.add_argument("--incumbent", required=True)
    ap.add_argument("--venv", required=True)
    ap.add_argument("--scripts", required=True)
    ap.add_argument("--shards", type=int, default=4)
    ap.add_argument("--stage", default="s2")
    ap.add_argument("--run-id-prefix", required=True)
    ap.add_argument("--host", required=True)
    args = ap.parse_args()

    rundir = Path(args.rundir)
    outdir = rundir / "settled"
    (outdir / "scores").mkdir(parents=True, exist_ok=True)
    py = args.venv
    S = args.scripts

    shard_preds = [rundir / f"{args.arm}-shard{i}.jsonl" for i in range(args.shards)]
    shard_metas = [Path(str(p) + ".meta.json") for p in shard_preds]
    for p in shard_preds + shard_metas:
        if not p.exists():
            raise SystemExit(f"ABORT: missing {p}")
    metas = [json.loads(p.read_text()) for p in shard_metas]
    incomplete = [m["run_id"] for m in metas if not m.get("complete")]
    if incomplete:
        raise SystemExit(f"ABORT: shards not complete: {incomplete}")

    merged = outdir / f"{args.arm}.jsonl"
    rows = 0
    pairs, cases_seen, models, ctx, ins, qs = set(), set(), set(), set(), set(), set()
    with open(merged, "w", encoding="utf-8") as out:
        for p in shard_preds:
            with open(p, encoding="utf-8") as fh:
                for line in fh:
                    row = json.loads(line)
                    key = (row["case_id"], row["event_index"])
                    if key in pairs:
                        raise SystemExit(f"ABORT: duplicate (case,event) {key}")
                    pairs.add(key)
                    cases_seen.add(row["case_id"])
                    models.add(row["model"])
                    ctx.add(row["context_variant"])
                    ins.add(row["instruction_variant"])
                    qs.add(row["question_variant"])
                    # Collapse the per-shard run_id onto the canonical arm run_id. The
                    # scorer's aggregate_system() treats a candidate carrying more than one
                    # run_id as mixed and refuses it, and the published merged artifacts do
                    # the same -- outputs/s3/openjev-full.jsonl carries the single value
                    # "s3-openjev-merged" on all 100,001 rows. Shard ids stay in meta.merge.
                    row["run_id"] = args.run_id_prefix
                    out.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
                    rows += 1

    sum_requests = sum(m["requests"] for m in metas)
    checks = {
        "rows_equal_shard_request_sum": rows == sum_requests,
        "rows_equal_distinct_pairs": rows == len(pairs),
        "single_model": len(models) == 1,
        "single_grid": len(ctx) == 1 and len(ins) == 1 and len(qs) == 1,
    }
    print(json.dumps({"rows": rows, "shard_request_sum": sum_requests,
                      "distinct_cases": len(cases_seen), "checks": checks}, indent=2))
    if not all(checks.values()):
        raise SystemExit("ABORT: merge integrity check failed")

    digest = sha256_file(merged)
    meta = {
        "actual_input_tokens": sum(m["actual_input_tokens"] for m in metas),
        "attempted_provider_calls": sum(m["attempted_provider_calls"] for m in metas),
        "cases": len(cases_seen),
        "cases_sha256": sha256_file(args.cases),
        "complete": True,
        "contexts": sorted(ctx),
        "estimated_usd": 0.0,
        "instruction_format": metas[0]["instruction_format"],
        "instructions": sorted(ins),
        "model": sorted(models)[0],
        "model_revision": metas[0]["model_revision"],
        "prediction_sha256": digest,
        "questions": sorted(qs),
        "requests": rows,
        "reserved_input_tokens": sum(m["reserved_input_tokens"] for m in metas),
        "run_id": f"{args.run_id_prefix}",
        "schema_version": "1",
        "stage": args.stage,
        "merge": {
            "shards": args.shards,
            "shard_run_ids": [m["run_id"] for m in metas],
            "rows_by_shard": [m["requests"] for m in metas],
            "shard_prediction_sha256": [m["prediction_sha256"] for m in metas],
        },
    }
    meta_path = Path(str(merged) + ".meta.json")
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    print(f"settled meta -> {meta_path}")

    # Re-verify the written digest against the bytes actually on disk.
    if sha256_file(merged) != json.loads(meta_path.read_text())["prediction_sha256"]:
        raise SystemExit("ABORT: on-disk digest does not match settled meta")
    print("on-disk digest matches settled meta: OK")

    auc = outdir / f"auc-variants-{args.arm}.json"
    mapc = outdir / f"mapping-check-{args.arm}.json"
    rbv = outdir / f"recall-by-variable-{args.arm}.json"
    score = outdir / "scores" / f"{args.run_id_prefix}.json"

    run([py, f"{S}/auc_variants.py", "--cases", args.cases, "--predictions", str(merged),
         "--label", args.arm, "--out", str(auc)], "auc-variants")
    run([py, f"{S}/mapping_check.py", "--cases", args.cases, "--predictions", str(merged),
         "--out", str(mapc)], "mapping-check")
    run([py, f"{S}/by_variable_27b.py", "--cases", args.cases, "--predictions", str(merged),
         "--label", args.arm, "--incumbent-predictions", args.incumbent,
         "--auc-variants", str(auc), "--out", str(rbv)], "recall-by-variable")
    # --prediction-schema defaults to a repo-relative path; pass it explicitly so the
    # scorer does not depend on cwd.
    run([py, f"{S}/benchmark_score_system_one.py", "--cases", args.cases,
         "--system-one-predictions", str(merged), "--output", str(score),
         "--prediction-schema", f"{S}/agree/cfg/system-one-prediction-v1.schema.json"],
        "scorecard")

    # Trap 3: the Space build asserts these agree to 5e-12.
    LEAD = "risk = 1 - P(allow)  [leaderboard variable]"
    a = json.loads(auc.read_text())["auc"][LEAD]
    b = json.loads(rbv.read_text())["by_variable"][LEAD]["roc_auc"]
    delta = abs(a - b)
    print(f"AUC cross-check lead variable: auc-variants={a!r} by_variable={b!r} delta={delta}")
    if delta > 5e-12:
        raise SystemExit(f"ABORT: AUC disagreement {delta} exceeds 5e-12 build tolerance")
    variables = sorted(json.loads(rbv.read_text())["by_variable"])
    if len(variables) != 4:
        raise SystemExit(f"ABORT: need 4 ranking variables, got {variables}")
    print(f"four variables OK: {variables}")

    startups = sorted(rundir.glob("startup-shard*.json"))
    freeze = {
        "kind": "defenseclaw-system-one-serving-provenance",
        "schema_version": "1",
        "stage": args.stage,
        "display_name": args.arm,
        "host": args.host,
        "cards": [f"cuda:{i} (one replica per card, no tensor parallelism)"
                  for i in range(args.shards)],
        "startup_provenance": [json.loads(p.read_text()) for p in startups],
        "resolved_stack": json.loads(run(
            [py, "-c",
             "import importlib.metadata as md, json, torch, subprocess\n"
             "pk=['torch','transformers','peft','tokenizers','safetensors','accelerate',"
             "'numpy','huggingface-hub','flash-linear-attention','triton']\n"
             "def v(p):\n"
             "    try: return md.version(p)\n"
             "    except Exception: return None\n"
             "print(json.dumps({'packages':{p:v(p) for p in pk},"
             "'torch':torch.__version__,'cuda':torch.version.cuda,"
             "'cudnn':torch.backends.cudnn.version(),"
             "'driver':subprocess.run(['nvidia-smi','--query-gpu=driver_version',"
             "'--format=csv,noheader'],capture_output=True,text=True).stdout.strip()"
             ".splitlines()[0],'gpu':torch.cuda.get_device_name(0),"
             "'capability':'.'.join(map(str,torch.cuda.get_device_capability(0)))}))"],
            "resolved stack")),
        "note_environment_mutability": (
            "Lightning studio image hydration completed AFTER ssh became usable and silently "
            "replaced accelerate (1.13.0->1.15.0) and removed flash-linear-attention, pip and "
            "the editable jev install underneath a running process. Both venvs were rebuilt "
            "with uv afterwards and these are the post-rebuild resolved versions. The absent "
            "batch_size=32 measurement for this arm is a casualty of that incident, NOT an "
            "out-of-memory condition."),
    }
    fz = outdir / f"{args.arm}.serving.json"
    fz.write_text(json.dumps(freeze, indent=2, sort_keys=True) + "\n")
    print(f"serving freeze -> {fz}")
    print("=== SETTLED OK ===")


if __name__ == "__main__":
    main()
