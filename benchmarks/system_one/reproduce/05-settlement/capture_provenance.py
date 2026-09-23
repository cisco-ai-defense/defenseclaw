"""Record the exact served artifact for one model, so every figure stays traceable.

Carries BOTH the friendly display name (used for keys and filenames) and the canonical
HuggingFace repo id plus pinned base revision and adapter revision, as required: the
display name disambiguates these ZefanCai adapters from our own unrelated self-hosted
"OpenJev" at revision 5ec9e5fd..., while the canonical ids remain the provenance.
"""
import argparse
import json
import subprocess
import urllib.request
from pathlib import Path

REGISTRY = {
    "open-jev-qwen-9b": {
        "repo_id": "ZefanCai/Open-Jev-9B",
        "repo_revision": "47e966881e489511c0c7f5633a9e1960a676a551",
        "base_model": "Qwen/Qwen3.5-9B",
        "base_revision": "c202236235762e1c871ad0ccb60c8ee5ba337b9a",
        "adapter_sha256": "f85650a8fb97c6d0ac3e948cdca2f30a0ca6ace8b8a43aebca1c152fe38aeb75",
        "head_sha256": "229fe9800384e824135e59d1af59bda7346da031aea61640be5f456b9be6ce70",
        "checkpoint_sha256": "9302c52feba99d079918755f2469f4f088266e9786327bab550248f3d83716d3",
        "temperature": 1.8969118766347646,
        "architecture": "LoRA rank 8 (alpha 16) on attention projections + trained scalar decision head",
        "readout": "independent_candidate_lora_nll_brier: one forward pass per candidate, "
                   "scalar head on the last hidden state, softmax over candidates / T",
        "loader": "jev.server (Open-Jev own loader; not vLLM/SGLang-servable)",
        "pinned_stack": {"transformers": "5.10.2", "peft": "0.19.1"},
        "max_length": 4096,
        "forward_passes_per_q2_decision": 7,
    },
    "open-jev-qwen-2b": {
        "repo_id": "ZefanCai/Open-Jev-2B",
        "repo_revision": "0c7aa498b1627be8da4acf34c863ff0ee0a92785",
        "base_model": "Qwen/Qwen3.5-2B",
        "base_revision": "15852e8c16360a2fea060d615a32b45270f8a8fc",
        "adapter_sha256": "2d23935b1a7380db444abac572c04646918ba794e59002d1588236182a3ca18f",
        "checkpoint_sha256": "3076462e6356412082e79af909227b39b2863b90def79155ca0821aa506b7ded",
        "temperature": 1.518796342858676,
        "architecture": "LoRA rank 8 (alpha 16) on attention projections + trained scalar decision head",
        "readout": "independent_candidate_lora_nll_brier: one forward pass per candidate, "
                   "scalar head on the last hidden state, softmax over candidates / T",
        "loader": "jev.server (Open-Jev own loader; not vLLM/SGLang-servable)",
        "pinned_stack": {"transformers": "5.10.2", "peft": "0.19.1"},
        "max_length": 4096,
        "forward_passes_per_q2_decision": 7,
    },
    "open-jev-qwen-27b": {
        "repo_id": "ZefanCai/Open-Jev-27B-v1.1",
        "repo_revision": "28cf73067d5b337860bbef3c85b8b82ba8730956",
        "base_model": "Qwen/Qwen3.8-27B",
        "base_revision": "1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0",
        "adapter_sha256": "1c857224bd3609c6a71eacf7f71dd021115fcc0f791936b1fc332e915b548a81",
        "adapter_revision": "28cf73067d5b337860bbef3c85b8b82ba8730956",
        "head_sha256": "76e382f122abfa4e0c467d860a8d142d2fb6d2a98dc0ef9e19870bfc6eb296b4",
        "temperature_sha256": "185c0b85539d195d02a2d4949295f0400fc208d9eb7ac4e5e6c97ebd339a235f",
        "checkpoint_sha256": "c49994563c3c4f04a99d9130203c4e526f4ae5086c84deec57698d18cb652e71",
        "temperature": 2.5343690298472983,
        "temperature_split": "calibration",
        "temperature_n": 512,
        "architecture": "LoRA rank 8 (alpha 16, dropout 0.0) + trained scalar decision head "
                        "nn.Linear(5120, 1). 160 resolved modules across all 64 layers: "
                        "in_proj_qkv + out_proj in the 48 linear-attention layers, "
                        "q/k/v/o_proj in the 16 full-attention layers (hybrid architecture). "
                        "320 F32 tensors, 15,466,496 adapter params + 5,121 head params "
                        "= 15,471,617 total.",
        "readout": "independent_candidate_lora_nll_brier: one forward pass per candidate, "
                   "scalar head on the last hidden state, softmax over candidates / T",
        "loader": "jev.server (Open-Jev own loader; not vLLM/SGLang-servable)",
        "pinned_stack": {"transformers": "5.10.2", "peft": "0.19.1"},
        "max_length": 4096,
        "forward_passes_per_q2_decision": 7,
        "licence": "apache-2.0 (code MIT)",
        "serving_overrides": {
            "replicas": 2,
            # The site prints `topology` instead of "N single-GPU replicas" when present, and
            # this arm is not N single-GPU replicas: it cannot be.
            "topology": "2 replicas, each pipeline-sharded across 2 NVIDIA L40S via accelerate "
                        "device_map=balanced (4 cards total). Not single-GPU replicas: the "
                        "resident language-model backbone is 47.73 GiB against 44.39 GiB usable "
                        "on one L40S, so two cards per replica is a floor rather than a choice. "
                        "No tensor parallelism; one inference at a time per replica.",
            "relationship_to_incumbent":
                "Same publisher, readout and loader as open-jev-qwen-9b and open-jev-qwen-2b "
                "(ZefanCai Open-Jev: LoRA r8 + trained scalar decision head, served through "
                "jev.server), at 27B on a different base family -- Qwen3.8-27B, whose 64 layers "
                "are hybrid: 48 linear-attention and 16 full-attention. It is unrelated to the "
                "self-hosted OpenJev incumbent at revision 5ec9e5fd despite the similar name. "
                "Served with eager attention, whereas the 2B and 9B arms ran the sdpa path "
                "hardcoded in jev/model.py; the measured divergence between the two paths on "
                "this checkpoint is recorded in "
                "openjev-qwen/validation/attn-agreement-open-jev-qwen-27b.json.",
            "sharding": "corpus stride shards rows[i::4] -- the same partition the 2B and 9B "
                        "used -- with the 4 runner shards mapped onto 2 model replicas "
                        "(shards 0,2 -> replica A; shards 1,3 -> replica B). Each replica is "
                        "pipeline-sharded across 2 L40S via accelerate device_map=balanced. "
                        "Two cards per replica is a floor, not a choice: the resident "
                        "language-model backbone is 47.73 GiB against 44.4 GiB usable on one "
                        "card. No tensor parallelism.",
            "gpu": "4x NVIDIA L40S 46068 MiB, 2 cards per replica",
            "attn_implementation": "eager",
            "dtype": "bfloat16",
            "candidate_batch_size": 4,
            "zero_layers_offloaded": True,
            "prefix_cache": False,
            "prefix_cache_reason": "Disabled, matching the 2B/9B arms. Open-Jev's opt-in "
                                   "request-local prefix cache was already rejected in this "
                                   "programme for failing a numeric A/B against the "
                                   "full-prefill path (worst probability delta 0.0311) while "
                                   "running 2.6x slower.",
        },
    },
    "bespoke-nimble-9b": {
        "repo_id": "bespokelabs/Bespoke-Nimble-9B",
        "repo_revision": "594dfdcfb6f94e3d0c0db7535180d3c71689169a",
        "base_model": "Qwen/Qwen3.5-9B",
        "base_revision": "c202236235762e1c871ad0ccb60c8ee5ba337b9a",
        "adapter_sha256": "ba7e28acb97f973e80fa51f3aa6fc6f75ea4081b89632ed45d8e5f3a1d7bfa6b",
        "adapter_revision": "93ec5d6ff1a9cd31d6cc0e0c58d312465d36de7c",
        "prompt_code_sha256": "a0a0f94d0f65e972bc20d088678ad3d595ff1c42b9c0d78f96034526303f63fc",
        "temperature": 2.179078721266035,
        "temperature_fitted": True,
        "architecture": "LoRA rank 16 (alpha 32) on attention + MLP projections, no separate head",
        "readout": "schema_candidate_classification_v1: one forward pass per schema field, "
                   "logits of the one-token letter codes from the LM head, softmax / T",
        "loader": "published inference.py scoring path, served on the /v1/systemone contract",
        "pinned_stack": {"transformers": "5.17.0", "peft": "0.21.0"},
        "trained_prompt_tokens": 2048,
        "max_length": 8192,
        "forward_passes_per_q2_decision": 3,
    },
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True, choices=sorted(REGISTRY))
    parser.add_argument("--out", required=True)
    parser.add_argument("--probe-port", type=int, help="optionally probe a live replica for /health")
    parser.add_argument("--stage", default="s2")
    parser.add_argument("--gpu-seconds", type=float)
    args = parser.parse_args()

    # Models that cannot be served the default way carry `serving_overrides`, which replace
    # the matching keys below. Without this the record would claim one single-GPU replica per
    # shard for a checkpoint that physically cannot fit on one card. Entries without the key
    # are unaffected.
    served = {key: value for key, value in REGISTRY[args.name].items()
              if key != "serving_overrides"}
    overrides = REGISTRY[args.name].get("serving_overrides", {})

    record = {
        "schema_version": "1",
        "kind": "defenseclaw-system-one-serving-provenance",
        "display_name": args.name,
        "stage": args.stage,
        "grid": "C7/I3/Q2",
        "served": served,
        "serving": {
            "transport": "POST /v1/systemone on 127.0.0.1, ssh -L tunnel from the dev host; "
                         "no port exposed publicly",
            "replicas": 4,
            "sharding": "corpus stride shards rows[i::4], one single-GPU replica per shard "
                        "(CUDA_VISIBLE_DEVICES; no tensor parallelism)",
            "gpu": "4x NVIDIA L40S 46068 MiB",
            "prefix_cache": False,
            "prefix_cache_reason": "Open-Jev's opt-in request-local prefix cache failed a numeric "
                                   "A/B against the full-prefill path (worst probability delta "
                                   "0.0311) and was 2.6x slower on this workload; rejected.",
            "engine": "PyTorch/transformers via each project's own loader. Neither vLLM nor SGLang "
                      "can serve Open-Jev: its decision comes from a trained scalar head on the "
                      "backbone's hidden state, not from token logits.",
        },
    }
    record["serving"].update(overrides)
    if args.gpu_seconds:
        record["gpu_seconds"] = args.gpu_seconds
        record["gpu_hours"] = round(args.gpu_seconds / 3600, 4)

    if args.probe_port:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{args.probe_port}/health", timeout=10) as response:
                record["live_health"] = json.loads(response.read())
        except OSError as error:
            record["live_health"] = {"error": str(error)}

    try:
        record["nvidia_smi"] = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=index,name,memory.total", "--format=csv,noheader"],
            text=True, stderr=subprocess.DEVNULL).strip().splitlines()
    except (OSError, subprocess.CalledProcessError):
        pass

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"written": str(out), "display_name": args.name,
                      "repo_id": record["served"]["repo_id"]}, sort_keys=True))


if __name__ == "__main__":
    main()
