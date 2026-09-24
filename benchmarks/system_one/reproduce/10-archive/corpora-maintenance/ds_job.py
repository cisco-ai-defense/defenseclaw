#!/usr/bin/env python3
"""Remove the augur-derived corpora from the private corpora archive.

Deletes the 5 files, records the exclusion under excluded/ following the mcptox
precedent, adds the LICENSES.md bullet following the nl2bash precedent, and
regenerates MANIFEST.json, SHA256SUMS and README.md so `sha256sum -c SHA256SUMS`
passes. Privacy is read before and after and any change aborts.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys

from huggingface_hub import CommitOperationAdd, CommitOperationDelete, HfApi, hf_hub_download

DS = "Vineethsain/defenseclaw-system-one-corpora-v1"
WORK = "$WORK/.ds-work"
STAGE = os.path.join(WORK, "stage")

TARGETS = [
    "corpora/intent-ablation/cases.jsonl",
    "corpora/intent-ablation/cases.manifest.json",
    "corpora/toolcall-labels/cases.jsonl",
    "corpora/toolcall-labels/cases-smoke20.jsonl",
    "corpora/toolcall-labels/cases.manifest.json",
]
EXPECT_BYTES = 35_300_371
LANES = ["intent-ablation", "toolcall-labels"]
AUGUR = "robustintelligence/augur_unsafe_tool_input_eval"

api = HfApi()

# ----------------------------------------------------------------- gate: privacy before
info = api.dataset_info(DS)
PRIV_BEFORE = info.private
print(f"privacy BEFORE : private={PRIV_BEFORE!r}  sha={info.sha}")
if PRIV_BEFORE is not True:
    print("ABORT: the archive is not private. Refusing to touch it.")
    raise SystemExit(2)

files_before = set(api.list_repo_files(DS, repo_type="dataset"))
print(f"files BEFORE   : {len(files_before)}")
missing = [t for t in TARGETS if t not in files_before]
if missing:
    print(f"ABORT: target(s) already absent: {missing}")
    raise SystemExit(2)

# ------------------------------------------------------------------------- pull metadata
os.makedirs(STAGE, exist_ok=True)


def pull(rel: str) -> str:
    p = hf_hub_download(DS, rel, repo_type="dataset")
    d = os.path.join(STAGE, rel)
    os.makedirs(os.path.dirname(d), exist_ok=True)
    shutil.copy(p, d)
    return d


man_p = pull("MANIFEST.json")
sums_p = pull("SHA256SUMS")
readme_p = pull("README.md")
lic_p = pull("LICENSES.md")
src_man = {ln: pull(f"corpora/{ln}/cases.manifest.json") for ln in LANES}

man = json.load(open(man_p))
removed = {t: man["files"][t] for t in TARGETS}
tot = sum(e["bytes"] for e in removed.values())
print(f"bytes to remove: {tot:,}  (expected {EXPECT_BYTES:,})")
if tot != EXPECT_BYTES:
    print("ABORT: byte total does not match the brief.")
    raise SystemExit(2)

# ------------------------------------------------- the exclusion records under excluded/
LOCK = {
    "license": "review-required",
    "license_status": "review_required",
    "redistribution": "aggregate-only",
    "revision": "toolcall-security-intent-v1",
    "source_url": f"https://huggingface.co/datasets/{AUGUR}",
}
NOTE = (
    "EXCLUDED. The internal licence review of "
    f"{AUGUR} concluded against holding its derived rows, so "
    "corpora/{lane}/ was deleted from this archive. This manifest is retained "
    "because it is aggregate statistics only: it carries no case text, no tool-call "
    "arguments and no case ids. The rows are reconstructible by fetching the upstream "
    "dataset at the revision above and re-running {script}."
)
SCRIPTS = {
    "intent-ablation": "benchmarks/scripts/build_intent_ablation.py",
    "toolcall-labels": "benchmarks/scripts/build_toolcall_label_cases.py",
}

new_excluded: dict[str, str] = {}
for lane in LANES:
    doc = json.load(open(src_man[lane]))
    doc["source"].update(LOCK)
    doc["source"]["publication_restriction"] = (
        "Aggregate numbers only. Do not upload this corpus, the upstream payloads, or any "
        "derived case file to HuggingFace or any other host."
    )
    doc["exclusion"] = {
        "excluded": True,
        "deleted_paths": sorted(t for t in TARGETS if t.startswith(f"corpora/{lane}/")),
        "deleted_bytes": sum(e["bytes"] for t, e in removed.items()
                             if t.startswith(f"corpora/{lane}/")),
        "reason": "internal licence review concluded against retention",
        "source_dataset": AUGUR,
        "note": NOTE.format(lane=lane, script=SCRIPTS[lane]),
        "precedent": "excluded/mcptox/cases.manifest.json",
    }
    rel = f"excluded/{lane}/cases.manifest.json"
    d = os.path.join(STAGE, rel)
    os.makedirs(os.path.dirname(d), exist_ok=True)
    with open(d, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
    new_excluded[rel] = d
    print(f"staged {rel}  {os.path.getsize(d):,} bytes")


def sha256(p: str) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- MANIFEST.json
for t in TARGETS:
    del man["files"][t]
for rel, p in new_excluded.items():
    man["files"][rel] = {"bytes": os.path.getsize(p), "sha256": sha256(p)}
man["files"] = {k: man["files"][k] for k in sorted(man["files"])}
man["file_count"] = len(man["files"])
man["total_bytes"] = sum(e["bytes"] for e in man["files"].values())
man["exclusions"] = man.get("exclusions", {})
man["exclusions"][AUGUR] = {
    "lanes": LANES,
    "deleted_paths": TARGETS,
    "deleted_bytes": tot,
    "reason": "internal licence review concluded against retention",
    "records_retained": sorted(new_excluded),
}
with open(man_p, "w", encoding="utf-8") as fh:
    json.dump(man, fh, indent=1, sort_keys=True)
    fh.write("\n")
print(f"MANIFEST.json  : file_count {man['file_count']}, total_bytes {man['total_bytes']:,}")

# ------------------------------------------------------------------------------ SHA256SUMS
rows: dict[str, str] = {}
for ln in open(sums_p, encoding="utf-8"):
    ln = ln.rstrip("\n")
    if not ln.strip():
        continue
    h, p = ln.split(None, 1)
    rows[p.strip()] = h
for t in TARGETS:
    rows.pop(t, None)
for rel, p in new_excluded.items():
    rows[rel] = sha256(p)
with open(sums_p, "w", encoding="utf-8") as fh:
    for p in sorted(rows):
        fh.write(f"{rows[p]}  {p}\n")
print(f"SHA256SUMS     : {len(rows)} lines")
assert set(rows) == set(man["files"]), "SHA256SUMS and MANIFEST disagree"

# --------------------------------------------------------------------------------- README
rd = open(readme_p, encoding="utf-8").read()
orig = rd

# 1. drop the two lane rows and the five Contents rows
kept = []
for line in rd.split("\n"):
    if re.match(r"^\| (intent-ablation|toolcall-labels) \| ", line):
        continue
    if re.match(r"^\| `corpora/(intent-ablation|toolcall-labels)/", line):
        continue
    if line.startswith(f"| `{AUGUR}` |"):
        continue
    kept.append(line)
rd = "\n".join(kept)

# 2. add the two excluded/ rows to Contents, keeping the block alphabetical
anchor = "| `excluded/mcptox/cases.manifest.json` | 2,600 | - | `77cc067391ac655768103113a3d032ad7be1ad7746e2666ad5dbbfce60a96045` |"
rows_ex = {anchor.split("`")[1]: anchor}
for rel, p in new_excluded.items():
    rows_ex[rel] = f"| `{rel}` | {os.path.getsize(p):,} | - | `{sha256(p)}` |"
block = "\n".join(rows_ex[k] for k in sorted(rows_ex))
rd = rd.replace(anchor, block)

# 3. rewrite Exclusion 2
start = rd.index("## Exclusion 2:")
end = rd.index("## What is not here")
rd = rd[:start] + (
    "## Exclusion 2: the augur-derived lanes are NOT here\n"
    "\n"
    f"`{AUGUR}` is recorded in\n"
    "the branch lock as `license: review-required`, `license_status:\n"
    "review_required`, `redistribution: aggregate-only`. That review concluded\n"
    "against retention. It was the sole source of the `intent-ablation` and\n"
    "`toolcall-labels` lanes, and both lanes have been deleted from this archive:\n"
    "\n"
    "| deleted path | bytes | rows |\n"
    "|---|---|---|\n"
    + "".join(
        f"| `{t}` | {removed[t]['bytes']:,} | "
        f"{format(removed[t]['rows'], ',') if removed[t].get('rows') else '-'} |\n"
        for t in TARGETS)
    + f"\nTotal removed: {tot:,} bytes across {len(TARGETS)} files.\n"
    "\n"
    "The two `cases.manifest.json` files are retained under `excluded/` because they\n"
    "are aggregate statistics only, carrying no case text, no tool-call arguments and\n"
    "no case ids. They record the lane's counts, its grade-C caveat, the labelling\n"
    "model and the upstream revision. This follows `excluded/mcptox/`.\n"
    "\n"
    "To reconstruct the deleted rows, fetch the upstream dataset at the revision\n"
    "above and re-run `benchmarks/scripts/build_intent_ablation.py` and\n"
    "`benchmarks/scripts/build_toolcall_label_cases.py`.\n"
    "\n"
    "Both lanes were diagnostic. Neither `s2` nor `s3` samples from them, so no ranked\n"
    "figure in the published Space rests on them. The findings that did rest on them\n"
    "were withdrawn with the data.\n"
    "\n") + rd[end:]

# 4. the licence table's prose reference to the 92nd lock entry
rd = rd.replace(
    f"The single added entry is\n`{AUGUR}`. Each row below says which\ncopy the value came from.",
    f"The single added entry is\n`{AUGUR}`, whose lanes have since been\ndeleted from this archive; see Exclusion 2. Each row below says which copy the\nvalue came from.")

if rd == orig:
    print("ABORT: README was not modified.")
    raise SystemExit(2)
open(readme_p, "w", encoding="utf-8").write(rd)
for pat in ("intent-ablation", "toolcall-labels"):
    n = len(re.findall(re.escape(f"corpora/{pat}/"), rd))
    print(f"README         : remaining `corpora/{pat}/` refs = {n}")

# ------------------------------------------------------------------------------ LICENSES.md
lic = open(lic_p, encoding="utf-8").read()
bullet = (
    f"- `{AUGUR}`: licence review-required\n"
    "  upstream, concluded against retention. Its derived `intent-ablation` and\n"
    "  `toolcall-labels` rows are **not** in this archive. See `README.md`.\n")
anchor2 = "- `AnishJoshi/nl2bash-custom`:"
j = lic.index(anchor2)
k = lic.index("\n\n", j) + 1
lic = lic[:k] + bullet + lic[k:]
open(lic_p, "w", encoding="utf-8").write(lic)
print("LICENSES.md    : augur bullet added after the nl2bash bullet")

# ------------------------------------------------------------------------------- one commit
ops: list = [CommitOperationDelete(path_in_repo=t) for t in TARGETS]
for rel, p in new_excluded.items():
    ops.append(CommitOperationAdd(path_in_repo=rel, path_or_fileobj=p))
for rel, p in (("MANIFEST.json", man_p), ("SHA256SUMS", sums_p),
               ("README.md", readme_p), ("LICENSES.md", lic_p)):
    ops.append(CommitOperationAdd(path_in_repo=rel, path_or_fileobj=p))

if "--dry-run" in sys.argv:
    print("\nDRY RUN. operations that would be committed:")
    for o in ops:
        print("   ", type(o).__name__, o.path_in_repo)
    raise SystemExit(0)

commit = api.create_commit(
    repo_id=DS, repo_type="dataset", operations=ops,
    commit_message="Remove the augur-derived intent-ablation and toolcall-labels lanes",
    commit_description=(
        f"The internal licence review of {AUGUR} concluded against retention. Its two "
        f"derived lanes are deleted: {len(TARGETS)} files, {tot:,} bytes.\n\n"
        + "".join(f"- {t} ({removed[t]['bytes']:,} B)\n" for t in TARGETS)
        + "\nEach lane's cases.manifest.json is retained under excluded/ as aggregate "
        "statistics only, carrying no case text, no tool-call arguments and no case ids, "
        "following excluded/mcptox/. MANIFEST.json, SHA256SUMS and README.md are "
        f"regenerated so sha256sum -c SHA256SUMS passes: {man['file_count']} tracked files "
        f"and {man['total_bytes']:,} bytes. LICENSES.md gains the bullet, following the "
        "AnishJoshi/nl2bash-custom precedent.\n\n"
        "Neither s2 nor s3 samples from these lanes. The archive stays private."))
print(f"\ncommit: {getattr(commit, 'oid', commit)}")

# ------------------------------------------------------------------ gate: privacy after
after = api.dataset_info(DS)
print(f"privacy AFTER  : private={after.private!r}  sha={after.sha}")
if after.private is not PRIV_BEFORE:
    print(f"ABORT: privacy changed {PRIV_BEFORE!r} -> {after.private!r}")
    raise SystemExit(2)
files_after = set(api.list_repo_files(DS, repo_type="dataset"))
print(f"files AFTER    : {len(files_after)}")
still = [t for t in TARGETS if t in files_after]
print("targets still present:", still or "none")
if still:
    raise SystemExit(2)
print("added:", sorted(files_after - files_before))
print("removed:", sorted(files_before - files_after))
