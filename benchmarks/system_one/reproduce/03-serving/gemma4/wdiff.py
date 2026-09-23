"""Which tensors did jevify's merged LoRA actually change, relative to the base?

The card says "LoRA r=64 on attention projections". On an MoE this matters: if the
fused 3-D expert parameters are untouched, the great majority of the model's
weights never saw the objective, and adapting them is headroom. This compares the
two checkpoints tensor by tensor and reports changed/unchanged parameter counts by
module class -- measured, not assumed.
"""

import json
import re
from collections import defaultdict
from pathlib import Path

import torch
from safetensors import safe_open

HUB = Path("/opt/dlami/nvme/hf/hub")
PINS = json.loads(Path("$WORK/g4j/pins.json").read_text())
BASE = "google/gemma-4-26B-A4B-it"
TUNED = "kushalpatil/jevify-gemma4-26b-a4b"


def snapshot(repo_id):
    return HUB / ("models--" + repo_id.replace("/", "--")) / "snapshots" / PINS[repo_id]


def shard_map(path):
    index = path / "model.safetensors.index.json"
    if index.exists():
        return json.loads(index.read_text())["weight_map"]
    return {}


def classify(name):
    leaf = name.split(".")[-2] if name.endswith(".weight") or name.endswith(".bias") else name.split(".")[-1]
    if re.search(r"(experts?)", name):
        return "moe_expert"
    if re.search(r"(q_proj|k_proj|v_proj|o_proj|qkv_proj)", name):
        return "attention_proj"
    if re.search(r"(gate_proj|up_proj|down_proj)", name):
        return "mlp_proj"
    if "router" in name or re.search(r"\bgate\b", name):
        return "router"
    if "norm" in name:
        return "norm"
    if "embed" in name or "lm_head" in name:
        return "embedding"
    return f"other:{leaf}"


def main():
    base_dir, tuned_dir = snapshot(BASE), snapshot(TUNED)
    base_map, tuned_map = shard_map(base_dir), shard_map(tuned_dir)
    assert base_map and tuned_map, "expected sharded checkpoints"
    names = sorted(set(base_map) | set(tuned_map))

    base_handles = {f: safe_open(str(base_dir / f), framework="pt", device="cpu") for f in sorted(set(base_map.values()))}
    tuned_handles = {f: safe_open(str(tuned_dir / f), framework="pt", device="cpu") for f in sorted(set(tuned_map.values()))}

    stats = defaultdict(lambda: {"tensors": 0, "params": 0, "changed_tensors": 0, "changed_params": 0,
                                 "max_abs_delta": 0.0, "max_rel_fro": 0.0})
    missing = {"base_only": [], "tuned_only": [], "shape_mismatch": []}
    changed_names = []
    for name in names:
        if name not in tuned_map:
            missing["base_only"].append(name)
            continue
        if name not in base_map:
            missing["tuned_only"].append(name)
            continue
        a = base_handles[base_map[name]].get_tensor(name)
        b = tuned_handles[tuned_map[name]].get_tensor(name)
        if a.shape != b.shape:
            missing["shape_mismatch"].append([name, list(a.shape), list(b.shape)])
            continue
        kind = classify(name)
        entry = stats[kind]
        entry["tensors"] += 1
        entry["params"] += a.numel()
        af, bf = a.float(), b.float()
        delta = (bf - af)
        max_abs = float(delta.abs().max())
        if max_abs > 0:
            denom = float(af.norm()) or 1.0
            entry["changed_tensors"] += 1
            entry["changed_params"] += a.numel()
            entry["max_abs_delta"] = max(entry["max_abs_delta"], max_abs)
            entry["max_rel_fro"] = max(entry["max_rel_fro"], float(delta.norm()) / denom)
            changed_names.append([name, list(a.shape), max_abs, float(delta.norm()) / denom])
        del a, b, af, bf, delta

    total = {"tensors": sum(v["tensors"] for v in stats.values()),
             "params": sum(v["params"] for v in stats.values()),
             "changed_tensors": sum(v["changed_tensors"] for v in stats.values()),
             "changed_params": sum(v["changed_params"] for v in stats.values())}
    total["changed_params_fraction"] = total["changed_params"] / total["params"] if total["params"] else None
    out = {"base": {"repo": BASE, "revision": PINS[BASE]},
           "tuned": {"repo": TUNED, "revision": PINS[TUNED]},
           "by_module_class": {k: dict(v) for k, v in sorted(stats.items())},
           "total": total, "missing": missing,
           "changed_tensor_examples": sorted(changed_names, key=lambda r: -r[3])[:12],
           "changed_tensor_count": len(changed_names),
           "torch": torch.__version__}
    print(json.dumps(out, indent=2))
    Path("$WORK/g4j/out/jevify-weight-diff.json").write_text(json.dumps(out, indent=2) + "\n")


if __name__ == "__main__":
    main()
