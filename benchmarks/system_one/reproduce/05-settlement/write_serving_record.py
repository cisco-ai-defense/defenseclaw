"""Emit the serving.json-style provenance record for the H200 System One stack."""
import importlib.metadata as md
import json
import os
import subprocess
import sys

import torch

PKGS = ["torch", "transformers", "peft", "tokenizers", "safetensors", "accelerate",
        "numpy", "huggingface-hub", "flash-linear-attention", "fla-core", "triton", "einops"]


def ver(pkg):
    try:
        return md.version(pkg)
    except Exception:
        return None


def sh(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()


root = os.path.expanduser("~/sysone")
record = {
    "kind": "defenseclaw-system-one-serving-provenance",
    "schema_version": "1",
    "stage": "h200-bringup",
    "display_name": "open-jev-qwen-2b",
    "grid": "C7/I3/Q2",
    "host": {
        "provider": "lightning.ai studio (free tier)",
        "gpu": torch.cuda.get_device_name(0),
        "gpu_count": torch.cuda.device_count(),
        "gpu_memory_mib": round(torch.cuda.get_device_properties(0).total_memory / 1048576),
        "compute_capability": ".".join(map(str, torch.cuda.get_device_capability(0))),
        "driver": sh("nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader"),
        "cpu_cores": os.cpu_count(),
    },
    "stack": {
        "python": sys.version.split()[0],
        "packages": {p: ver(p) for p in PKGS},
        "torch_cuda": torch.version.cuda,
        "torch_cudnn": torch.backends.cudnn.version(),
        "torch_arch_list": torch.cuda.get_arch_list(),
        "pinned_stack": {"transformers": ver("transformers"), "peft": ver("peft")},
    },
    "served": {
        "repo_id": "ZefanCai/Open-Jev-2B",
        "base_model": "Qwen/Qwen3.5-2B",
        "base_revision": "15852e8c16360a2fea060d615a32b45270f8a8fc",
        "repo_revision": "0c7aa498b1627be8da4acf34c863ff0ee0a92785",
        "adapter_sha256": "2d23935b1a7380db444abac572c04646918ba794e59002d1588236182a3ca18f",
        "checkpoint_sha256": "3076462e6356412082e79af909227b39b2863b90def79155ca0821aa506b7ded",
        "temperature": 1.518796342858676,
        "max_length": 4096,
        "forward_passes_per_q2_decision": 7,
        "loader": "jev.server (Open-Jev own loader; not vLLM/SGLang-servable)",
        "loader_code_commit": sh("git", "-C", f"{root}/Open-Jev", "rev-parse", "HEAD"),
        "loader_code_commit_matches_published": (
            sh("git", "-C", f"{root}/Open-Jev", "rev-parse", "HEAD")
            == "ed45657bf726c3b77408942830e5578f99df904e"),
    },
    "serving": {
        "engine": "PyTorch/transformers via Open-Jev's own loader",
        "dtype": "bfloat16",
        "attn_implementation": "sdpa",
        "attn_note": (
            "sdpa is hardcoded in jev/model.py at commit ed45657b with no override. The "
            "'eager' control recorded for open-jev-qwen-27b comes from the separate j27 "
            "serve27.py wrapper, which monkey-patches the load call; it does not apply to "
            "the 2B/9B arms."),
        "prefix_cache": False,
        "batch_size": 32,
        "replicas_measured": [1, 2],
        "sharding": "corpus stride shards rows[i::N], one single-GPU replica per shard",
        "transport": "POST /v1/systemone on 127.0.0.1 only; no port exposed off-host",
        "request_serialisation": (
            "jev/server.py holds a threading.Lock around inference, so client concurrency "
            "cannot batch across requests and cannot perturb numerics."),
    },
    "divergence_from_l40s_baseline": {
        "hardware": "L40S sm_89 -> H200 sm_90 (different SDPA kernel selection)",
        "torch": "L40S torch version unrecorded; H200 is torch 2.14.0+cu130",
        "cuda": "H200 CUDA 13.0 / driver 580.178.04",
        "fix_applied": (
            "python3.12-dev was missing, so Triton could not compile its driver shim "
            "(Python.h not found) and flash-linear-attention silently fell back to CPU. "
            "Installing the headers restored the fused path; before the fix throughput was "
            "~99 rows/min with the GPU at 0%."),
        "unclosable_unknown": (
            "The L40S GPU serving venv was never captured. reproduce-bundle/00-environment "
            "holds only requirements-frozen.client-venv.txt. flash-linear-attention 0.5.0 is "
            "documented in the Open-Jev reference docs/resources.md; causal-conv1d is "
            "documented nowhere, so the residual transformers 'fast path' warning is most "
            "likely present on both hosts."),
    },
}
print(json.dumps(record, indent=2, sort_keys=True))
with open(f"{root}/agree/out/serving-h200-open-jev-qwen-2b.json", "w") as handle:
    json.dump(record, handle, indent=2, sort_keys=True)
    handle.write("\n")
