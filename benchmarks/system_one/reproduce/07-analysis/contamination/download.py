import json, os, sys, hashlib
from huggingface_hub import hf_hub_download

CACHE = "$WORK/.system-one-data/outputs/secjudge/contamination/cache"
os.makedirs(CACHE, exist_ok=True)

TARGETS = {
 "S-Labs/prompt-injection-dataset": ["data/train.csv","data/validation.csv","data/test.csv"],
 "AnishJoshi/nl2bash-custom": ["data/train.json","data/dev.json","data/test.json"],
 "ise-uiuc/Magicoder-OSS-Instruct-75K": ["data-oss_instruct-decontaminated.jsonl"],
 "Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset": ["CyberSec-Dataset_escaped.jsonl"],
 "3nesdeniz/agentic-prompt-injection-boundary-pairs": ["data/train.jsonl","data/validation.jsonl","data/test.jsonl"],
 "deepset/prompt-injections": ["data/train-00000-of-00001-9564e8b05b4757ab.parquet","data/test-00000-of-00001-701d16158af87368.parquet"],
 "infraset/infraset": ["data/runs.parquet","data/commands.parquet","data/tasks.parquet","data/execution-summary.jsonl"],
 "rogue-security/coding-agent-security-benchmark": ["data/test-00000-of-00001.parquet","README.md"],
 "nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1": ["train.jsonl","README.md"],
}
EXTRA_READMES = ["S-Labs/prompt-injection-dataset","AnishJoshi/nl2bash-custom","3nesdeniz/agentic-prompt-injection-boundary-pairs","infraset/infraset","Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset","ise-uiuc/Magicoder-OSS-Instruct-75K","deepset/prompt-injections"]
for r in EXTRA_READMES:
    if "README.md" not in TARGETS[r]:
        TARGETS[r] = TARGETS[r] + ["README.md"]

only = sys.argv[1] if len(sys.argv)>1 else None
res = {}
for repo, files in TARGETS.items():
    if only and only != repo: continue
    res[repo] = {}
    for f in files:
        try:
            p = hf_hub_download(repo_id=repo, filename=f, repo_type="dataset", local_dir=os.path.join(CACHE, repo.replace("/","__")))
            st = os.path.getsize(p)
            h = hashlib.sha256()
            with open(p,"rb") as fh:
                for chunk in iter(lambda: fh.read(1<<20), b""): h.update(chunk)
            res[repo][f] = {"ok": True, "path": p, "bytes": st, "sha256": h.hexdigest()}
            print("OK", repo, f, st, flush=True)
        except Exception as e:
            res[repo][f] = {"ok": False, "error_type": type(e).__name__, "error": str(e)[:500]}
            print("FAIL", repo, f, type(e).__name__, str(e)[:200], flush=True)
out = "$WORK/.system-one-data/outputs/secjudge/contamination/work/downloads%s.json" % ("_"+only.replace("/","__") if only else "")
with open(out,"w") as fh: json.dump(res, fh, indent=2)
print("WROTE", out)
