"""Write a settled meta for a merged s2 prediction file.

The runner writes a meta per shard; the merged file produced by merge_s2_halves.py gets
only a merge attestation. Published figures are held to "meta complete:true AND on-disk
sha256 == prediction_sha256", so the merged file needs its own meta in the same shape the
runner emits, plus the serving provenance the leaderboard needs for traceability:
canonical repo id alongside the display name, base model + base revision, and adapter
revision + sha256.
"""
import argparse
import hashlib
import json
from pathlib import Path

REGISTRY = json.loads(Path(__file__).with_name("serving_registry.json").read_text()) \
    if Path(__file__).with_name("serving_registry.json").exists() else {}


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--merged", required=True)
    parser.add_argument("--merge-json", required=True)
    parser.add_argument("--serving-json", required=True)
    parser.add_argument("--shard-meta", action="append", required=True)
    args = parser.parse_args()

    merged = Path(args.merged)
    merge = json.loads(Path(args.merge_json).read_text())
    serving = json.loads(Path(args.serving_json).read_text())
    served = serving["served"]
    shards = [json.loads(Path(p).read_text()) for p in args.shard_meta]
    verification = merge["verification"]

    digest = sha256_file(merged)
    if digest != merge["merged_sha256"]:
        raise SystemExit(f"on-disk sha256 {digest} != merge attestation {merge['merged_sha256']}")
    incomplete = [s.get("run_id") for s in shards if s.get("complete") is not True]
    if incomplete:
        raise SystemExit(f"shards not complete: {incomplete}")
    if verification["coverage_complete"] is not True:
        raise SystemExit("merge coverage incomplete")
    if verification["errors_by_code"]:
        raise SystemExit(f"error rows present: {verification['errors_by_code']}")

    meta = {
        "schema_version": "1",
        "complete": True,
        "prediction_sha256": digest,
        "requests": verification["rows"],
        "cases": verification["corpus_cases"],
        "cases_sha256": merge["corpus"]["cases_sha256"],
        "run_id": merge["merged_run_id"],
        "model": serving["display_name"],
        "model_revision": verification["model_revision"],
        "contexts": ["C7"],
        "instructions": ["I3"],
        "questions": ["Q2"],
        "grid": "C7/I3/Q2",
        "instruction_format": "structured",
        "actual_input_tokens": sum(int(s.get("actual_input_tokens", 0)) for s in shards),
        "estimated_usd": 0.0,
        "errors_by_code": verification["errors_by_code"],
        "routes": verification["routes"],
        # provenance: friendly name for keys, canonical ids for traceability
        "display_name": serving["display_name"],
        "repo_id": served["repo_id"],
        "repo_revision": served.get("repo_revision"),
        "base_model": served["base_model"],
        "base_revision": served["base_revision"],
        "adapter_sha256": served.get("adapter_sha256"),
        "adapter_revision": served.get("adapter_revision"),
        "head_sha256": served.get("head_sha256"),
        "checkpoint_sha256": served.get("checkpoint_sha256"),
        "temperature": served.get("temperature"),
        "readout": served.get("readout"),
        "loader": served.get("loader"),
        "pinned_stack": served.get("pinned_stack"),
        "max_length": served.get("max_length"),
        "forward_passes_per_decision": served.get("forward_passes_per_q2_decision"),
        "serving": serving["serving"],
        "merge": {"merge_json": str(args.merge_json), "merged_sha256": merge["merged_sha256"],
                  "shards": len(shards), "rows_by_shard": verification["rows_by_half"],
                  "case_id_overlap": verification["case_id_overlap_between_halves"],
                  "duplicate_case_event_pairs": verification["duplicate_case_event_pairs"]},
        "shard_run_ids": [s.get("run_id") for s in shards],
        "shard_prediction_sha256": [s.get("prediction_sha256") for s in shards],
    }
    if "gpu_seconds" in serving:
        meta["gpu_seconds"] = serving["gpu_seconds"]
        meta["gpu_hours"] = serving.get("gpu_hours")

    out = Path(str(merged) + ".meta.json")
    out.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"written": str(out), "complete": True, "requests": meta["requests"],
                      "prediction_sha256": digest, "repo_id": meta["repo_id"],
                      "display_name": meta["display_name"]}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
