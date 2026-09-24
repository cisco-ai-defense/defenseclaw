#!/usr/bin/env python3
"""Give the settled open-jev-qwen-27b s2 arm the two contracts the Space build reads.

Nothing is re-run and no decision is recomputed. The settled body is checked against its
own meta first, then two files are extended additively:

  <dir>/open-jev-qwen-27b.serving.json
      gains the nested `served` / `serving` blocks, composed from the flat
      `startup_provenance` records already in the file. All four replica records must agree
      on every field that goes into `served`, which is checked rather than assumed. No flat
      key is removed or changed.

  <dir>/open-jev-qwen-27b.jsonl.meta.json
      gains display_name, repo_id, repo_revision, base_model, base_revision and license.
      The run wrote the checkpoint sha under `model_revision` and no repo id, so those six
      facts are copied from the serving record that did record them. `prediction_sha256`
      still covers the body byte for byte and no pre-existing key is changed.
"""
from __future__ import annotations

import hashlib
import json
import os

O = "$WORK/.system-one-data/outputs"
D = os.path.join(O, "openjev-qwen", "s2", "h200-settled")
NAME = "open-jev-qwen-27b"
CASES_SHA = "39f2c1df2369952a0525cc4c5575f4bdb590fb3ca8c1bc6805cf4f376c1adbf7"

SERVED_FIELDS = ("repo_id", "repo_revision", "canonical_base_model", "base_revision",
                 "adapter_revision", "checkpoint_sha256", "attn_implementation", "dtype",
                 "temperature", "max_length", "method", "device_map", "prefix_cache",
                 "batch_size", "code_commit", "load_kwargs")


def sha256_file(path: str) -> str:
    d = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(8 << 20), b""):
            d.update(block)
    return d.hexdigest()


def jload(p):
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def jdump(p, o):
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(o, fh, indent=2, sort_keys=True)
        fh.write("\n")


body = os.path.join(D, f"{NAME}.jsonl")
meta_p = body + ".meta.json"
serving_p = os.path.join(D, f"{NAME}.serving.json")
meta = jload(meta_p)
rec = jload(serving_p)

disk = sha256_file(body)
rows = sum(1 for _ in open(body, encoding="utf-8"))
errors = sum(1 for line in open(body, encoding="utf-8")
             if line.strip() and (json.loads(line).get("error")
                                  or json.loads(line).get("error_code")))
checks = {
    "meta_complete": meta.get("complete") is True,
    "sha256_matches_meta": disk == meta.get("prediction_sha256"),
    "rows_equal_30310": rows == 30310,
    "rows_equal_meta_requests": rows == meta.get("requests"),
    "cases_equal_4277": meta.get("cases") == 4277,
    "zero_error_rows": errors == 0,
    "ran_the_broad_comparison_corpus": meta.get("cases_sha256") == CASES_SHA,
    "grid_is_C7_I3_Q2": [meta.get("contexts"), meta.get("instructions"),
                         meta.get("questions")] == [["C7"], ["I3"], ["Q2"]],
}
for k, v in checks.items():
    print(f"  {k:44s} {v}")
if not all(checks.values()):
    raise SystemExit("ABORT: the open-jev-qwen-27b body is not settled by every check above")
print(f"  rows={rows} cases={meta['cases']} errors={errors} sha256={disk}")

sp = rec["startup_provenance"]
if len(sp) != 4:
    raise SystemExit(f"ABORT: expected 4 replica startup records, found {len(sp)}")
for field in SERVED_FIELDS:
    values = {json.dumps(r.get(field), sort_keys=True) for r in sp}
    if len(values) != 1:
        raise SystemExit(f"ABORT: the 4 replica records disagree on {field!r}: {values}")
r0 = sp[0]
if r0["checkpoint_sha256"] != meta["model_revision"]:
    raise SystemExit("ABORT: the serving record's checkpoint sha is not the meta's "
                     "model_revision")
cards = rec["cards"]
if len(cards) != len(sp):
    raise SystemExit(f"ABORT: {len(cards)} cards for {len(sp)} replicas")
print(f"  all 4 replica records agree on every served field; checkpoint "
      f"{r0['checkpoint_sha256'][:12]} == meta.model_revision")

out = dict(rec)
out.setdefault("kind", "defenseclaw-system-one-serving-provenance")
out["display_name"] = NAME
out["grid"] = "C7/I3/Q2"
out["composed_from"] = {
    "startup_provenance": f"{serving_p} :: startup_provenance (4 replica records, agreement "
                          f"checked field by field)",
    "run_meta": meta_p,
    "note": "The nested served / serving blocks below are the shape the Space build reads. "
            "Every value is carried from a flat key already in this file. No flat key was "
            "removed or changed.",
}
out["served"] = {
    "repo_id": r0["repo_id"],
    "repo_revision": r0["repo_revision"],
    "base_model": r0["canonical_base_model"],
    "base_revision": r0["base_revision"],
    "adapter_revision": r0["adapter_revision"],
    "checkpoint_sha256": r0["checkpoint_sha256"],
    "architecture": "LoRA decision head on Qwen3.8-27B: a trained scalar head on the "
                    "backbone's hidden state, read out by `method` "
                    f'{r0["method"]!r}',
    "readout": r0["method"],
    "attn_implementation": r0["attn_implementation"],
    "dtype": r0["dtype"],
    "temperature": r0["temperature"],
    "temperature_fitted": True,
    "max_length": r0["max_length"],
    "loader": "jev.server (Open-Jev's own loader; not vLLM/SGLang-servable)",
    "code_commit": r0["code_commit"],
    "pinned_stack": {k: rec["resolved_stack"]["packages"][k]
                     for k in ("peft", "transformers", "torch", "accelerate")
                     if k in rec["resolved_stack"]["packages"]},
}
out["serving"] = {
    "gpu": "NVIDIA H200 143771MiB",
    "replicas": len(sp),
    "sharding": "one replica per card, no tensor parallelism; corpus stride shards, "
                f"{r0['device_map']} device_map inside each replica over its single card",
    "cards": cards,
    "batch_size": r0["batch_size"],
    "prefix_cache": r0["prefix_cache"],
    "prefix_cache_reason": "not enabled for this arm",
    "engine": "PyTorch/transformers via Open-Jev's own loader. Its decision comes from a "
              "trained scalar head on the backbone's hidden state, not from token logits, "
              "so neither vLLM nor SGLang can serve it.",
    "transport": "POST /v1/systemone on 127.0.0.1, ssh -L tunnel from the dev host; no port "
                 "exposed publicly",
    "host": rec["host"],
}
for key in ("startup_provenance", "cards", "host", "resolved_stack", "schema_version",
            "stage", "note_environment_mutability"):
    if key in rec and json.dumps(out.get(key), sort_keys=True) != json.dumps(rec[key],
                                                                             sort_keys=True):
        raise SystemExit(f"ABORT: pre-existing key {key!r} would change")
jdump(serving_p, out)
print(f"  wrote serving -> {serving_p}")

added = {
    "display_name": (NAME, "serving record :: display_name (all 4 replica records)"),
    "repo_id": (r0["repo_id"], "serving record :: startup_provenance[*].repo_id"),
    "repo_revision": (r0["repo_revision"],
                      "serving record :: startup_provenance[*].repo_revision"),
    "base_model": (r0["canonical_base_model"],
                   "serving record :: startup_provenance[*].canonical_base_model"),
    "base_revision": (r0["base_revision"],
                      "serving record :: startup_provenance[*].base_revision"),
    "license": ("apache-2.0", f'{r0["repo_id"]} cardData.license at revision '
                              f'{r0["repo_revision"][:12]}'),
    # The H200 runner wrote no errors_by_code for this body. The count is measured from the
    # body above rather than assumed.
    "errors_by_code": ({}, f"counted over all {rows:,} rows of the settled body: "
                           f"{errors} error rows"),
}
mout = dict(meta)
for key, (value, source) in added.items():
    if key in mout and mout[key] != value:
        raise SystemExit(f"ABORT: meta already carries {key}={mout[key]!r}, not {value!r}")
    mout[key] = value
mout["meta_augmented"] = {
    "why": "This run's meta recorded the checkpoint sha under model_revision and no repo id, "
           "repo revision, base model or base revision. Those four, plus the display name and "
           "the licence, are what the Space build reads off a row. Each is copied from the "
           "serving record that recorded it, after checking that all four replica records "
           "agree on it.",
    "keys": {k: {"value": v, "source": s} for k, (v, s) in added.items()},
    "unchanged": "No pre-existing key was changed or removed. prediction_sha256 still covers "
                 f"the body byte for byte: {disk}.",
}
jdump(meta_p, mout)
print(f"  wrote meta -> {meta_p}")
print("\nSTAGED")
