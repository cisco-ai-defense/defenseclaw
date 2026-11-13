#!/usr/bin/env python3
"""Download the competitor model weights into one HF_HOME (run where a Hugging Face token with the Meta licence accepted is set up;
the token is never copied). The weights are never committed or redistributed: each project's own licence applies
(Llama 4 Community Licence for Prompt Guard 2 and Llama Guard 4, Apache-2.0 / MIT for the others).

  python3 fetch_models.py --hf-home ~/cmp/hf [--gpu]
Writes <hf-home>/MODELS.json with the resolved revision of every repo.
"""
import argparse, json, os

CPU = [  # (repo, revision or None = main, kind)
    ("meta-llama/Llama-Prompt-Guard-2-86M", None, "llamafirewall"),
    ("meta-llama/Llama-Prompt-Guard-2-22M", None, "llamafirewall"),
    ("protectai/deberta-v3-base-prompt-injection-v2", "89b085cd330414d3e7d9dd787870f315957e1e9f", "hub"),   # LLM Guard's and Invariant's pinned PI model
    ("nvidia/NemoGuard-JailbreakDetect", None, "hub"),
    ("Snowflake/snowflake-arctic-embed-m-long", None, "hub"),
    ("nomic-ai/nomic-bert-2048", None, "hub"),          # remote code the Snowflake embedder loads
    ("openai-community/gpt2-large", None, "hub"),      # NeMo jailbreak heuristics perplexity model ("gpt2-large")
    ("GuardrailsAI/prompt-saturation-attack-detector", None, "hub"),   # Guardrails AI DetectJailbreak
    ("google-bert/bert-base-cased", None, "hub"),
    ("sentence-transformers/all-MiniLM-L6-v2", None, "hub"),
    ("zhx123/ftrobertallm", None, "hub"),
]
ALLOW = ["*.json", "*.safetensors", "*.txt", "*.model", "*.onnx", "*.py", "*.jinja", "*.md", "onnx/*", "*.bin", "*.pkl"]
GPU = [("meta-llama/Llama-Guard-4-12B", None, "hub")]


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--hf-home", required=True); ap.add_argument("--gpu", action="store_true"); ap.add_argument("--only", default="")
    a = ap.parse_args()
    from huggingface_hub import HfApi, snapshot_download
    api = HfApi(); out = {}
    path = os.path.join(a.hf_home, "MODELS.json")
    if os.path.exists(path):
        out = json.load(open(path))
    for repo, rev, kind in (GPU if a.gpu else CPU):
        if a.only and repo not in a.only.split(","):
            continue
        sha = api.model_info(repo, revision=rev).sha
        if kind == "llamafirewall":   # LlamaFirewall loads $HF_HOME/<org>--<name> (save_pretrained layout)
            snapshot_download(repo, revision=sha, local_dir=os.path.join(a.hf_home, repo.replace("/", "--")))
        else:
            snapshot_download(repo, revision=sha, cache_dir=os.path.join(a.hf_home, "hub"), allow_patterns=ALLOW)
        out[repo] = sha
        print(repo, sha, flush=True)
    json.dump(out, open(path, "w"), indent=1)


if __name__ == "__main__":
    main()
