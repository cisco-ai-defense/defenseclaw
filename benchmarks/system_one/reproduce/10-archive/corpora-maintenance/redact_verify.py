import hashlib, json, re
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
ROOT = {".gitattributes", "LICENSES.md", "MANIFEST.json", "README.md", "SHA256SUMS",
        "REDACTIONS.json"}
print(f"repo {len(repo)}  SHA256SUMS {len(sums)}  MANIFEST {len(man['files'])}")
print("SHA256SUMS lists a path absent from repo:", sorted(set(sums) - repo) or "none")
print("repo payload missing from SHA256SUMS   :", sorted(repo - set(sums) - ROOT) or "none")
print("MANIFEST vs SHA256SUMS:", "identical" if set(man["files"]) == set(sums) else "DIFFER")
print("digests agree:", all(man["files"][p]["sha256"] == sums[p] for p in sums))
NEW = {"corpora/terminalbench/cases.jsonl":
       "1afe0774c33df35524b5c54969a201d1c32813598e1bf169a3044c5e23d49bac",
       "corpora/terminalbench/development-with-context.jsonl":
       "06cf02556d9a1285475b2fe918aa3ca3765b18d5bc28bfcfa99c6615fb205727",
       "corpora/terminalbench/partitioned/development.jsonl":
       "e31669beaa67a624c44ffb6ea00173ac7d8cd6340734126cf0949fbc29ddfa75"}
OLD = ["e752ee61baa77341d7c8191180816dee931361e5ac4d92a07936428013265b3e",
       "d82366c9c76dac275b426660c9ace594eaae4816c38e7bcc0970d825c732024e",
       "d677fa68d72f90f15bcf900e49490b64d48ec9a5c334e809c2e04845ec924d5b",
       "4d972e21f7c59d910fa5d944627dcd7c0557a3894d79181ab47e5ee4794ae004"]
print("\n--- the shipped bytes, downloaded and hashed ---")
PLACEHOLDER = "hf_" + "REDACTED" * 4 + "RE"
HF_DOC = "hf_" + "abcdefghijklmnopqrstuvwxyz123456"  # synthetic fixture; split on vendoring
CRED = re.compile(rb"\bhf_[A-Za-z0-9]{20,}\b")
for rel, exp in NEW.items():
    p = hf_hub_download(DS, rel, repo_type="dataset", revision=info.sha)
    h = hashlib.sha256(open(p, "rb").read()).hexdigest()
    body = open(p, "rb").read()
    counts = {}
    for m in CRED.finditer(body):
        s = m.group(0).decode(); counts[s] = counts.get(s, 0) + 1
    unk = {s: n for s, n in counts.items() if s not in (PLACEHOLDER, HF_DOC)}
    print(f"  {'OK  ' if h == exp and not unk else 'FAIL'} {rel}")
    print(f"       sha256 == post-redaction: {h == exp}   listed digest matches: {sums[rel] == h}")
    print(f"       placeholder {counts.get(PLACEHOLDER,0)}x, doc placeholder "
          f"{counts.get(HF_DOC,0)}x, unknown {len(unk)}")
print("\n--- old digests remaining in the dataset's own metadata ---")
for name in ("MANIFEST.json", "SHA256SUMS", "README.md", "REDACTIONS.json",
             "corpora/terminalbench/cases.manifest.json",
             "corpora/terminalbench/partitioned/development.manifest.json",
             "corpora/terminalbench/partitioned/splits.json",
             "corpora/terminalbench/partitioned/test.manifest.json",
             "corpora/terminalbench/partitioned/validation.manifest.json"):
    b = open(hf_hub_download(DS, name, repo_type="dataset", revision=info.sha),
             encoding="utf-8").read()
    hits = [o[:12] for o in OLD if o in b]
    role = "documented as pre-redaction provenance" if hits else "no old digest"
    print(f"  {name:62s} {len(hits)} old digest(s)  <- {role}")
print("\nREDACTIONS.json present:", "REDACTIONS.json" in repo)
