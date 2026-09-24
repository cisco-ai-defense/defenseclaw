import hashlib, json
from huggingface_hub import hf_hub_download, HfApi

api = HfApi()

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(8 << 20), b""):
            h.update(c)
    return h.hexdigest()

TC = "Vineethsain/defenseclaw-slm-toolcall-v1"
PR = "Vineethsain/defenseclaw-system-one-predictions-v1"

man = {}
for tree, repo, t in [("toolcall", TC, "cohort-settled-2026-09-24"),
                      ("predictions", PR, "system-one-s3-2026-09-24")]:
    recs = json.load(open("$WORK/hf-stage/%s/MANIFEST-%s.json" % (tree, t)))["records"]
    man[repo] = {r["path"]: r for r in recs}

samples = {
    TC: ["predictions-s3/deberta-v3-prompt-injection-v2.jsonl",
         "predictions-s3/shieldgemma-2b.jsonl.meta.json",
         "predictions/deberta-v3-prompt-injection-v2.jsonl",
         "predictions/llama-guard-3-1b.jsonl",
         "ranking/cohort-rank.json",
         "cpu/inventory.json"],
    PR: ["runs/nimble-s3/settled/bespoke-nimble-9b.jsonl",
         "runs/nimble-s3/settled/bespoke-nimble-9b.jsonl.meta.json",
         "runs/2b-s3/open-jev-qwen-2b-shard0.jsonl",
         "runs/9b-s3/open-jev-qwen-9b-shard0.jsonl",
         "reshard/chunks.json",
         "supervisor/state.json"],
}

ok = bad = 0
for repo, paths in samples.items():
    for p in paths:
        lp = hf_hub_download(repo, p, repo_type="dataset", force_download=True)
        got = sha(lp)
        exp = man[repo][p]["sha256"]
        m = (got == exp)
        ok += m
        bad += (not m)
        tag = "OK  " if m else "FAIL"
        print("%s %-26s %-52s %s" % (tag, repo.split("/")[-1][:26], p, got[:16]))

print("")
print("refetched=%d match=%d mismatch=%d" % (ok + bad, ok, bad))
print("=== FINAL PRIVACY + SHA FOR ALL FIVE ===")
for r in ["defenseclaw-slm-toolcall-v1",
          "defenseclaw-system-one-predictions-v1",
          "defenseclaw-system-one-evaluations-v1",
          "defenseclaw-system-one-corpora-v1",
          "defenseclaw-system-one-contamination-v1"]:
    rid = "Vineethsain/" + r
    i = api.repo_info(rid, repo_type="dataset")
    n = len(api.list_repo_files(rid, repo_type="dataset"))
    print("%-44s private=%s sha=%s files=%d" % (r, i.private, i.sha, n))
