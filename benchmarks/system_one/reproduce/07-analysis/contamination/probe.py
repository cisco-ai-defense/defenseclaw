import json, os, sys, traceback
from huggingface_hub import HfApi

REPOS = [
  ("S-Labs/prompt-injection-dataset", "train-source-2"),
  ("AnishJoshi/nl2bash-custom", "train-source-3"),
  ("ise-uiuc/Magicoder-OSS-Instruct-75K", "train-source-6"),
  ("Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset", "train-source-8"),
  ("3nesdeniz/agentic-prompt-injection-boundary-pairs", "train-source-9"),
  ("deepset/prompt-injections", "train-source-10"),
  ("infraset/infraset", "train-source-11"),
  ("rogue-security/coding-agent-security-benchmark", "eval-source"),
  ("nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1", "eval-source"),
  ("nvidia/Nemotron-RL-Agentic-Terminal-Pivot-v1", "our-s3-source"),
]

api = HfApi()
out = {}
for repo, role in REPOS:
    rec = {"repo_id": repo, "role": role}
    try:
        info = api.dataset_info(repo, files_metadata=True)
        rec["status"] = "reachable"
        rec["gated"] = getattr(info, "gated", None)
        rec["private"] = getattr(info, "private", None)
        rec["sha"] = getattr(info, "sha", None)
        rec["downloads"] = getattr(info, "downloads", None)
        cd = getattr(info, "cardData", None) or {}
        try:
            rec["card_configs"] = json.loads(json.dumps(cd.get("configs"), default=str))
        except Exception:
            rec["card_configs"] = None
        rec["card_dataset_info"] = json.loads(json.dumps(cd.get("dataset_info"), default=str)) if cd.get("dataset_info") else None
        rec["card_license"] = cd.get("license")
        files = []
        for s in (info.siblings or []):
            files.append({"path": s.rfilename, "size": getattr(s, "size", None)})
        rec["files"] = files
        rec["n_files"] = len(files)
    except Exception as e:
        rec["status"] = "error"
        rec["error_type"] = type(e).__name__
        rec["error"] = str(e)[:800]
    out[repo] = rec
    print(repo, "->", rec["status"], rec.get("gated"), rec.get("n_files"), rec.get("error_type",""), flush=True)

with open("$WORK/.system-one-data/outputs/secjudge/contamination/work/probe.json","w") as f:
    json.dump(out, f, indent=2)
print("WROTE probe.json")
