"""Exact weight-byte accounting from safetensors headers only (no tensor data read).

Tells us what `DecisionModel.__init__` must hold at peak (the whole
Qwen3_5ForConditionalGeneration) versus what stays resident after it keeps only
`full.model.language_model` and drops the vision tower, lm_head and mtp head.
That difference decides how many cards a shard needs and how many shards fit.
"""
import collections
import json
import pathlib
import struct

BASE = pathlib.Path("/opt/dlami/nvme/model-staging/qwen3.8-27b")

DTYPE_BYTES = {"F64": 8, "F32": 4, "F16": 2, "BF16": 2, "I64": 8, "I32": 4,
               "I16": 2, "I8": 1, "U8": 1, "BOOL": 1, "F8_E4M3": 1, "F8_E5M2": 1}

totals = collections.Counter()
dtypes = collections.Counter()
grand = 0

for shard in sorted(BASE.glob("model-*-of-*.safetensors")):
    with shard.open("rb") as handle:
        (header_len,) = struct.unpack("<Q", handle.read(8))
        header = json.loads(handle.read(header_len))
    for name, spec in header.items():
        if name == "__metadata__":
            continue
        count = 1
        for dim in spec["shape"]:
            count *= dim
        nbytes = count * DTYPE_BYTES[spec["dtype"]]
        grand += nbytes
        dtypes[spec["dtype"]] += nbytes
        if name.startswith("model.language_model"):
            bucket = "LM: " + ("layers" if ".layers." in name else name)
        elif name.startswith("model.visual"):
            bucket = "vision tower"
        elif name.startswith("mtp"):
            bucket = "mtp head"
        else:
            bucket = name
        totals[bucket] += nbytes

GiB = 2 ** 30
print("=== dtypes ===")
for dtype, nbytes in dtypes.most_common():
    print("  %-8s %10.3f GiB" % (dtype, nbytes / GiB))

print("=== buckets ===")
for bucket, nbytes in sorted(totals.items(), key=lambda kv: -kv[1]):
    print("  %-40s %10.3f GiB" % (bucket, nbytes / GiB))

lm = sum(v for k, v in totals.items() if k.startswith("LM: "))
print("=== capacity summary ===")
print("  grand total (peak during from_pretrained) %10.3f GiB" % (grand / GiB))
print("  language_model only (resident backbone)   %10.3f GiB" % (lm / GiB))
print("  dropped after del full                    %10.3f GiB" % ((grand - lm) / GiB))
print("  one L40S usable (45,460 MiB reported)     %10.3f GiB" % (45460 / 1024))
print("  two  L40S usable                          %10.3f GiB" % (2 * 45460 / 1024))
