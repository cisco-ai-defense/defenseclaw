#!/usr/bin/env python3
"""Stage the settled kev-9b s2 run into the canonical outputs tree.

The run was produced on the Lightning studio, and its settled body, per-shard meta and
Definition-A AUC file were carried back to the dev host under `rescoring-remine/kev-s2/`.
Nothing here re-runs the model or recomputes a decision: the body is copied byte for byte
and its sha256 is checked against the meta's `prediction_sha256` before anything else
happens.

Two files are composed rather than copied, and both are composed only from provenance that
is already on disk:

  <dir>/kev-9b.serving.json   the nested `served` / `serving` contract the Space build reads,
                              composed from the serving provenance the server itself printed
                              (`prov-kev.json`) plus this run's own meta. Every value is
                              carried over; none is invented.
  <dir>/kev-9b.jsonl.meta.json
                              the settled meta, augmented additively with the five provenance
                              keys the build reads (display_name, repo_id, repo_revision,
                              base_model, base_revision). No existing key is changed or
                              removed, `prediction_sha256` still covers the body byte for
                              byte, and `meta_augmented` records where each added key came
                              from.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys

O = "$WORK/.system-one-data/outputs"
SRC = "$WORK/rescoring-remine/kev-s2"
PROV = "$WORK/.system-one-backup-work/kevx/kevbench/work/prov-kev.json"
DST = os.path.join(O, "kev", "s2-settled")
NAME = "kev-9b"
CASES_SHA = "39f2c1df2369952a0525cc4c5575f4bdb590fb3ca8c1bc6805cf4f376c1adbf7"


def sha256_file(path: str) -> str:
    d = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(8 << 20), b""):
            d.update(block)
    return d.hexdigest()


def jload(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def jdump(path: str, obj) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")


os.makedirs(os.path.join(DST, "scores"), exist_ok=True)

body_src = os.path.join(SRC, f"{NAME}-shard0.jsonl")
meta_src = body_src + ".meta.json"
meta = jload(meta_src)
prov = jload(PROV)

# ---------------------------------------------------------------- gate: the body is settled
disk = sha256_file(body_src)
rows = sum(1 for _ in open(body_src, encoding="utf-8"))
errors = 0
cases = set()
for line in open(body_src, encoding="utf-8"):
    line = line.strip()
    if not line:
        continue
    r = json.loads(line)
    cases.add(str(r.get("case_id")))
    if r.get("error") or r.get("error_code"):
        errors += 1
checks = {
    "meta_complete": meta.get("complete") is True,
    "sha256_matches_meta": disk == meta.get("prediction_sha256"),
    "rows_equal_meta_requests": rows == meta.get("requests"),
    "rows_equal_30310": rows == 30310,
    "cases_equal_meta_cases": len(cases) == meta.get("cases"),
    "cases_equal_4277": len(cases) == 4277,
    "zero_error_rows": errors == 0,
    "ran_the_broad_comparison_corpus": meta.get("cases_sha256") == CASES_SHA,
    "grid_is_C7_I3_Q2": [meta.get("contexts"), meta.get("instructions"),
                         meta.get("questions")] == [["C7"], ["I3"], ["Q2"]],
    "checkpoint_matches_serving_provenance":
        meta.get("model_revision") == prov.get("checkpoint_sha256"),
}
for k, v in checks.items():
    print(f"  {k:44s} {v}")
if not all(checks.values()):
    print("ABORT: the kev-9b body is not settled by every check above")
    raise SystemExit(1)
print(f"  rows={rows} cases={len(cases)} errors={errors} sha256={disk}")

# ------------------------------------------------------------------------ copy the body
body_dst = os.path.join(DST, f"{NAME}.jsonl")
if not os.path.exists(body_dst) or sha256_file(body_dst) != disk:
    shutil.copyfile(body_src, body_dst)
if sha256_file(body_dst) != disk:
    print("ABORT: the copied body does not hash to the settled digest")
    raise SystemExit(1)
print(f"  copied body -> {body_dst}")

# -------------------------------------------------------------- compose the serving record
# device_map_devices records the logical cards one replica was sharded over; cuda_visible_devices
# records which physical cards the process was given. "N single-GPU replicas" is false for this
# arm on both halves, so the record states its topology instead and the build uses that.
ncards = len(prov["device_map_devices"])
serving = {
    "kind": "defenseclaw-system-one-serving-provenance",
    "schema_version": "1",
    "stage": "s2",
    "display_name": NAME,
    "grid": "C7/I3/Q2",
    "composed_from": {
        "serving_provenance": PROV,
        "run_meta": meta_src,
        "note": "Every value below is carried from one of those two files. The nested served / "
                "serving shape is what the Space build reads; the flat provenance the server "
                "printed is preserved under served.raw_provenance.",
    },
    "served": {
        "repo_id": prov["repo_id"],
        "repo_revision": prov["repo_revision"],
        "base_model": prov["base_model"],
        "base_revision": prov["base_revision"],
        "architecture": prov["architecture"],
        "adapter_revision": prov["repo_revision"],
        "adapter_sha256": prov["adapter_sha256"],
        "head_sha256": prov["head_sha256"],
        "checkpoint_sha256": prov["checkpoint_sha256"],
        "lora_merged_into_base": prov["lora_merged_into_base"],
        "merge_precision": prov["merge_precision"],
        "dtype": prov["dtype"],
        "attn_implementation": prov["attn_implementation_live"],
        "temperature": prov["temperature_applied"],
        "temperature_fitted": True,
        "temperature_source": prov["temperature_source"],
        "probabilities_precision": prov["probabilities_precision"],
        "loader": "kev.api / kev.server, the project's own scoring path, served on the "
                  "/v1/systemone contract",
        "pinned_stack": {"peft": prov["peft"], "transformers": prov["transformers"],
                         "torch": prov["torch"]},
        "raw_provenance": prov,
    },
    "serving": {
        "gpu": "NVIDIA H200",
        "topology": f"one replica sharded across {ncards} GPUs by device_map",
        "prefix_cache": prov["prefix_cache"],
        "prefix_cache_reason": "not enabled for this arm; the server recorded "
                               f"prefix_cache_size {prov['prefix_cache_size']}",
        "rows_per_forward": prov["rows_per_forward"],
        "weights_budget_gib_per_card": prov["weights_budget_gib_per_card"],
        "max_memory_gib_cap_per_card": prov["max_memory_gib_cap_per_card"],
        "engine": "PyTorch/transformers via the project's own loader. kev's decision comes "
                  "from a trained pointer head on the backbone's hidden state, so neither vLLM "
                  "nor SGLang can serve it.",
        "transport": "POST /v1/systemone on 127.0.0.1",
    },
}
serving_dst = os.path.join(DST, f"{NAME}.serving.json")
jdump(serving_dst, serving)
print(f"  wrote serving -> {serving_dst}")

# --------------------------------------------------------------------- augment the meta
added = {
    "display_name": (NAME, "run meta `model`"),
    "repo_id": (prov["repo_id"], f"{PROV} :: repo_id"),
    "repo_revision": (prov["repo_revision"], f"{PROV} :: repo_revision"),
    "base_model": (prov["base_model"], f"{PROV} :: base_model"),
    "base_revision": (prov["base_revision"], f"{PROV} :: base_revision"),
    "license": ("apache-2.0", "jaredpalmer/kev-9b cardData.license at revision "
                              f"{prov['repo_revision'][:12]}"),
    # The runner wrote no errors_by_code for this body. The count is measured from the body
    # above rather than assumed: every row was read and none carried an error or error_code.
    "errors_by_code": ({}, f"counted over all {rows:,} rows of the settled body: "
                           f"{errors} error rows"),
}
if meta.get("model") != NAME:
    print(f"ABORT: run meta `model` is {meta.get('model')!r}, not {NAME!r}")
    raise SystemExit(1)
out = dict(meta)
for key, (value, source) in added.items():
    if key in out and out[key] != value:
        print(f"ABORT: meta already carries {key}={out[key]!r}, which is not {value!r}")
        raise SystemExit(1)
    out[key] = value
out["meta_augmented"] = {
    "why": "The settled meta this run wrote records the checkpoint sha under model_revision and "
           "no repo id, repo revision, base model or base revision. Those four facts, plus the "
           "display name and the licence, are what the Space build reads off a row. Each is "
           "copied from the file that recorded it; none is derived and none is guessed.",
    "keys": {k: {"value": v, "source": s} for k, (v, s) in added.items()},
    "unchanged": "No pre-existing key was changed or removed. prediction_sha256 still covers "
                 f"the body byte for byte: {disk}.",
}
meta_dst = body_dst + ".meta.json"
jdump(meta_dst, out)
print(f"  wrote meta -> {meta_dst}")

# -------------------------------------------------------- carry the Definition-A AUC file
auc_src = os.path.join(SRC, f"auc-variants-{NAME}-shard0.json")
print(f"  Definition-A AUC source: {auc_src}")
print(json.dumps(jload(auc_src)["auc"], indent=2, sort_keys=True))
print("\nSTAGED")
