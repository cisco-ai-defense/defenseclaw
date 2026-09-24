import hashlib, json, os
from huggingface_hub import HfApi, hf_hub_download
DS = "Vineethsain/defenseclaw-system-one-corpora-v1"
api = HfApi(); info = api.dataset_info(DS)
print("rev:", info.sha, " private:", info.private)
repo = set(api.list_repo_files(DS, repo_type="dataset"))
sp = hf_hub_download(DS, "SHA256SUMS", repo_type="dataset", revision=info.sha)
mp = hf_hub_download(DS, "MANIFEST.json", repo_type="dataset", revision=info.sha)
sums = {}
for ln in open(sp):
    ln = ln.rstrip()
    if ln.strip():
        h, p = ln.split(None, 1); sums[p.strip()] = h
man = json.load(open(mp))
ROOT = {".gitattributes", "LICENSES.md", "MANIFEST.json", "README.md", "SHA256SUMS"}
print("repo files:", len(repo), " SHA256SUMS lines:", len(sums), " MANIFEST files:", len(man["files"]))
print("SHA256SUMS lists a path absent from the repo:", sorted(set(sums) - repo) or "none")
print("repo payload path missing from SHA256SUMS :", sorted(repo - set(sums) - ROOT) or "none")
print("MANIFEST vs SHA256SUMS path sets:", "identical" if set(man["files"]) == set(sums)
      else sorted(set(man["files"]) ^ set(sums)))
print("MANIFEST digests agree with SHA256SUMS:", all(man["files"][p]["sha256"] == sums[p] for p in sums))
print("file_count field:", man["file_count"], "consistent:", man["file_count"] == len(man["files"]))
print("total_bytes field:", f'{man["total_bytes"]:,}',
      "consistent:", man["total_bytes"] == sum(e["bytes"] for e in man["files"].values()))
print()
print("--- byte-level digest spot check (download + hash) ---")
check = ["excluded/intent-ablation/cases.manifest.json",
         "excluded/toolcall-labels/cases.manifest.json",
         "excluded/mcptox/cases.manifest.json",
         "corpora/intent-pairs/cases.manifest.json",
         "corpora/s2/cases.manifest.json"]
for rel in check:
    if rel not in sums:
        print(f"  {rel}: NOT LISTED"); continue
    p = hf_hub_download(DS, rel, repo_type="dataset", revision=info.sha)
    h = hashlib.sha256(open(p, "rb").read()).hexdigest()
    ok = (h == sums[rel]) and (os.path.getsize(p) == man["files"][rel]["bytes"])
    print(f"  {'OK  ' if ok else 'FAIL'} {rel}  bytes={os.path.getsize(p):,}")
print()
print("--- the deleted paths are gone from every metadata file ---")
rd = open(hf_hub_download(DS, "README.md", repo_type="dataset", revision=info.sha)).read()
for pat in ["corpora/intent-ablation/cases.jsonl", "corpora/toolcall-labels/cases.jsonl",
            "corpora/toolcall-labels/cases-smoke20.jsonl"]:
    print(f"  {pat}: in repo={pat in repo}  in SHA256SUMS={pat in sums}  in MANIFEST={pat in man['files']}")
print("  README still documents them only as deleted rows:",
      rd.count("Exclusion 2: the augur-derived lanes are NOT here") == 1)
