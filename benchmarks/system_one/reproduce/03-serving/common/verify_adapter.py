"""Verify the staged adapter matches the architecture claimed for it, from headers only.

The brief supplies these as measured facts; this re-derives them from the artifact so the
published provenance is checked rather than copied: 160 resolved LoRA modules across all 64
layers (in_proj_qkv + out_proj in the 48 linear-attention layers, q/k/v/o_proj in the 16
full-attention layers), 320 F32 tensors, 15,466,496 adapter params, and a head of
nn.Linear(5120, 1) at 5,121 params.
"""
import collections
import json
import pathlib
import re
import struct

CK = pathlib.Path("/opt/dlami/nvme/model-staging/open-jev-27b-v1.1/package/checkpoint")
BASE = pathlib.Path("/opt/dlami/nvme/model-staging/qwen3.8-27b")

DTYPE_BYTES = {"F32": 4, "F16": 2, "BF16": 2, "F64": 8}

with (CK / "adapter" / "adapter_model.safetensors").open("rb") as handle:
    (header_len,) = struct.unpack("<Q", handle.read(8))
    header = json.loads(handle.read(header_len))
header.pop("__metadata__", None)

dtypes = collections.Counter()
params = 0
modules = set()
per_kind = collections.Counter()
layers = set()
for name, spec in header.items():
    dtypes[spec["dtype"]] += 1
    count = 1
    for dim in spec["shape"]:
        count *= dim
    params += count
    # e.g. base_model.model.layers.31.self_attn.q_proj.lora_A.weight
    module = re.sub(r"\.lora_[AB]\.weight$", "", name)
    modules.add(module)
    match = re.search(r"\.layers\.(\d+)\.", name)
    if match:
        layers.add(int(match.group(1)))
    for kind in ("in_proj_qkv", "out_proj", "q_proj", "k_proj", "v_proj", "o_proj"):
        if f".{kind}." in name:
            per_kind[kind] += 1
            break

layer_types = json.load(open(BASE / "config.json"))["text_config"]["layer_types"]
type_counts = collections.Counter(layer_types)

# Which projection kinds appear in which layer type
kinds_by_layer_type = collections.defaultdict(set)
for name in header:
    match = re.search(r"\.layers\.(\d+)\.", name)
    if not match:
        continue
    for kind in ("in_proj_qkv", "out_proj", "q_proj", "k_proj", "v_proj", "o_proj"):
        if f".{kind}." in name:
            kinds_by_layer_type[layer_types[int(match.group(1))]].add(kind)
            break

print("=== adapter_model.safetensors ===")
print("  tensors           :", sum(dtypes.values()), dict(dtypes))
print("  resolved modules  :", len(modules))
print("  adapter params    :", f"{params:,}")
print("  layers covered    :", len(layers), "(min %d max %d)" % (min(layers), max(layers)))
print("  tensors by kind   :", dict(sorted(per_kind.items())))
print("  modules by kind   :", {k: v // 2 for k, v in sorted(per_kind.items())})
print("=== base layer types ===")
print("  ", dict(type_counts))
for layer_type, kinds in sorted(kinds_by_layer_type.items()):
    print(f"  {layer_type}: {sorted(kinds)}")

import torch  # noqa: E402

head = torch.load(CK / "head.pt", map_location="cpu", weights_only=True)
head_params = sum(tensor.numel() for tensor in head.values())
print("=== head.pt ===")
for key, tensor in head.items():
    print(f"  {key}: shape={tuple(tensor.shape)} dtype={tensor.dtype}")
print("  head params       :", f"{head_params:,}")
print("=== totals ===")
print("  adapter + head    :", f"{params + head_params:,}")

expected = {"tensors": 320, "modules": 160, "adapter_params": 15466496,
            "head_params": 5121, "total": 15471617, "layers": 64}
observed = {"tensors": sum(dtypes.values()), "modules": len(modules),
            "adapter_params": params, "head_params": head_params,
            "total": params + head_params, "layers": len(layers)}
print("=== check vs briefed facts ===")
for key, want in expected.items():
    got = observed[key]
    print(f"  {key:16s} expected={want:<12} observed={got:<12} {'OK' if got == want else 'MISMATCH'}")
print("  all_match:", observed == expected)
