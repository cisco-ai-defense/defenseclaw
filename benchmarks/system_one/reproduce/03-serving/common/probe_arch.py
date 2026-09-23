"""Cheap config-only probe: layer types, hidden size, and which attn_implementation
values the architecture will accept. Loads no weights."""
import json
import sys

BASE = "/opt/dlami/nvme/model-staging/qwen3.8-27b"
REV = "1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0"

cfg = json.load(open(BASE + "/config.json"))


def flat(d, prefix=""):
    for key, value in d.items():
        path = prefix + key
        if isinstance(value, dict):
            yield from flat(value, path + ".")
        elif isinstance(value, list) and len(value) > 12:
            uniq = sorted({str(v) for v in value})
            yield path, "list of %d, unique=%s, first6=%s" % (len(value), uniq, value[:6])
        else:
            yield path, value


print("=== config.json ===")
for path, value in flat(cfg):
    print("  %-46s %s" % (path, value))

import torch
import transformers
from transformers import AutoConfig, AutoModelForImageTextToText

print("=== versions ===")
print("  torch", torch.__version__, "transformers", transformers.__version__)
print("  visible cuda devices:", torch.cuda.device_count())
for i in range(torch.cuda.device_count()):
    free, total = torch.cuda.mem_get_info(i)
    print("   cuda:%d %s free=%.0f MiB total=%.0f MiB"
          % (i, torch.cuda.get_device_name(i), free / 2**20, total / 2**20))

conf = AutoConfig.from_pretrained(BASE, revision=REV)
print("=== AutoConfig ===")
print("  class:", type(conf).__name__)
text = getattr(conf, "text_config", conf)
print("  text_config class:", type(text).__name__)
for attr in ("num_hidden_layers", "hidden_size", "layer_types", "full_attention_interval",
             "num_attention_heads", "num_key_value_heads", "torch_dtype", "vocab_size"):
    if hasattr(text, attr):
        value = getattr(text, attr)
        if isinstance(value, list) and len(value) > 12:
            from collections import Counter
            value = "list of %d %s" % (len(value), dict(Counter(value)))
        print("  text.%-28s %s" % (attr, value))

print("=== supported attn implementations ===")
for cls_name in ("AutoModelForImageTextToText",):
    pass
model_cls = AutoModelForImageTextToText
# Resolve the concrete class from the config without instantiating weights.
from transformers.models.auto.modeling_auto import MODEL_FOR_IMAGE_TEXT_TO_TEXT_MAPPING
concrete = MODEL_FOR_IMAGE_TEXT_TO_TEXT_MAPPING[type(conf)]
print("  concrete class:", concrete.__name__)
for attr in ("_supports_sdpa", "_supports_flash_attn", "_supports_flex_attn",
             "_supports_attention_backend", "_can_record_outputs"):
    print("  %-30s %s" % (attr, getattr(concrete, attr, "<absent>")))

try:
    from transformers.masking_utils import ALL_MASK_ATTENTION_FUNCTIONS
    print("  mask fns:", sorted(ALL_MASK_ATTENTION_FUNCTIONS._global_mapping.keys()))
except Exception as exc:  # noqa: BLE001
    print("  mask fns unavailable:", exc)
try:
    from transformers.modeling_utils import ALL_ATTENTION_FUNCTIONS
    print("  attn fns:", sorted(ALL_ATTENTION_FUNCTIONS._global_mapping.keys()))
except Exception as exc:  # noqa: BLE001
    print("  attn fns unavailable:", exc)

print("=== index: language-model tensor bytes vs total ===")
index = json.load(open(BASE + "/model.safetensors.index.json"))
meta = index.get("metadata", {})
print("  metadata:", meta)
weight_map = index["weight_map"]
prefixes = {}
for name in weight_map:
    top = ".".join(name.split(".")[:3])
    prefixes[top] = prefixes.get(top, 0) + 1
for key in sorted(prefixes):
    print("  %-52s %d tensors" % (key, prefixes[key]))
