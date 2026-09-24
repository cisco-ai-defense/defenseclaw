#!/usr/bin/env python3
"""Ship the credential-redacted terminalbench corpora into corpora-v1.

The redaction was applied upstream and is length-preserving: a 37-byte string matching the
HuggingFace user access token format was replaced by a same-length placeholder drawn from the
same character class, so every row still exercises credential detection and no file changed
size. Only digests moved.

This pass:
  * re-verifies the staged bytes against the expected post-redaction digests, and re-verifies
    that no unknown credential-shaped string survives, before anything is uploaded
  * uploads the three redacted corpus files
  * moves `output_sha256` in the affected manifests to the shipped bytes
  * records the redaction in every affected manifest and in a repository-level ledger, carrying
    BOTH digests, because the settled prediction bodies were produced against the pre-redaction
    input and a row's context_sha256 reproduces only from that one
  * regenerates MANIFEST.json, SHA256SUMS and README.md
  * reads privacy before and after and aborts on any change

`source_corpus_sha256` is deliberately left at the pre-redaction value. It states which bytes a
partition was cut from, which is a fact about the past, and the redaction block beside it says
so. No prediction body, run meta, scorecard or log is modified by this pass.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys

from huggingface_hub import CommitOperationAdd, HfApi, hf_hub_download

DS = "Vineethsain/defenseclaw-system-one-corpora-v1"
STAGE_SRC = "$WORK/.s1-archive-stage/corpora-v1"
WORK = "$WORK/.ds-work/redact"

PLACEHOLDER = "hf_" + "REDACTED" * 4 + "RE"
HF_DOC = "hf_" + "abcdefghijklmnopqrstuvwxyz123456"  # synthetic fixture; split on vendoring
KNOWN = {PLACEHOLDER, HF_DOC}
CRED = re.compile(rb"\bhf_[A-Za-z0-9]{20,}\b")

# path in repo -> (occurrences replaced, sha before, sha after)
REDACTED = {
    "corpora/terminalbench/cases.jsonl": (
        78, "d82366c9c76dac275b426660c9ace594eaae4816c38e7bcc0970d825c732024e",
        "1afe0774c33df35524b5c54969a201d1c32813598e1bf169a3044c5e23d49bac"),
    "corpora/terminalbench/development-with-context.jsonl": (
        78, "d677fa68d72f90f15bcf900e49490b64d48ec9a5c334e809c2e04845ec924d5b",
        "06cf02556d9a1285475b2fe918aa3ca3765b18d5bc28bfcfa99c6615fb205727"),
    "corpora/terminalbench/partitioned/development.jsonl": (
        78, "4d972e21f7c59d910fa5d944627dcd7c0557a3894d79181ab47e5ee4794ae004",
        "e31669beaa67a624c44ffb6ea00173ac7d8cd6340734126cf0949fbc29ddfa75"),
}
# redacted but NOT part of this dataset; carried in the ledger for completeness
NOT_IN_DATASET = {
    "s1-n1000/terminalbench-context-cases.jsonl": (
        12, "e752ee61baa77341d7c8191180816dee931361e5ac4d92a07936428013265b3e",
        "83ecdd214616d5f07dbbeb234c8e7b100db8de0fa4ca82337ff19244a40ee1cf"),
}
# metadata files whose output_sha256 describes a redacted file
MANIFEST_FIXES = {
    "corpora/terminalbench/cases.manifest.json": "corpora/terminalbench/cases.jsonl",
    "corpora/terminalbench/partitioned/development.manifest.json":
        "corpora/terminalbench/partitioned/development.jsonl",
}
TOUCH_ONLY = ["corpora/terminalbench/partitioned/test.manifest.json",
              "corpora/terminalbench/partitioned/validation.manifest.json",
              "corpora/terminalbench/partitioned/splits.json"]

NOTE = ("Settled prediction bodies were produced against the pre-redaction input, so a row's "
        "context_sha256 reproduces from sha256_before_redaction and not from the file shipped "
        "here. No prediction body, run meta, scorecard or log was modified.")

api = HfApi()


def sha256(p: str) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 22), b""):
            h.update(c)
    return h.hexdigest()


# ------------------------------------------------------------- gate: privacy and the payload
info = api.dataset_info(DS)
PRIV_BEFORE = info.private
print(f"privacy BEFORE : private={PRIV_BEFORE!r}  sha={info.sha}")
if PRIV_BEFORE is not True:
    print("ABORT: the archive is not private.")
    raise SystemExit(2)

print("\n--- verifying the staged bytes before anything is uploaded ---")
bad = 0
for rel, (occ, before, after) in REDACTED.items():
    src = os.path.join(STAGE_SRC, rel)
    if not os.path.exists(src):
        print(f"ABORT: staged file missing: {src}")
        raise SystemExit(2)
    got = sha256(src)
    size = os.path.getsize(src)
    counts: dict[str, int] = {}
    with open(src, "rb") as fh:
        for m in CRED.finditer(fh.read()):
            s = m.group(0).decode()
            counts[s] = counts.get(s, 0) + 1
    unknown = {s: n for s, n in counts.items() if s not in KNOWN}
    ok_sha = got == after
    ok_occ = counts.get(PLACEHOLDER, 0) == occ
    print(f"  {rel}")
    print(f"    sha256 matches the post-redaction value : {ok_sha}")
    print(f"    placeholder occurrences                 : {counts.get(PLACEHOLDER, 0)} "
          f"(expected {occ}) {ok_occ}")
    print(f"    unknown credential-shaped strings        : {len(unknown)}")
    print(f"    bytes                                    : {size:,}")
    if not (ok_sha and ok_occ) or unknown:
        bad += 1
if bad:
    print("ABORT: the staged payload did not verify. Nothing uploaded.")
    raise SystemExit(2)
print("staged payload verified: digests match, only known placeholders present")

os.makedirs(WORK, exist_ok=True)


def pull(rel: str) -> str:
    p = hf_hub_download(DS, rel, repo_type="dataset")
    d = os.path.join(WORK, rel)
    os.makedirs(os.path.dirname(d), exist_ok=True)
    shutil.copy(p, d)
    return d


# --------------------------------------------------------------------- the affected manifests
def redaction_block(rel: str) -> dict:
    occ, before, after = REDACTED[rel]
    return {
        "applied": True,
        "kind": "post-hoc credential redaction",
        "target": rel,
        "what": ("a 37-byte string matching the HuggingFace user access token format was replaced "
                 "with a same-length placeholder of the same character class, so the rows still "
                 "exercise credential detection"),
        "length_preserving": True,
        "bytes_unchanged": True,
        "occurrences_replaced": occ,
        "sha256_before_redaction": before,
        "sha256_after_redaction": after,
        "predictions_untouched": True,
        "note": NOTE,
    }


changed: dict[str, str] = {}
for rel, target in MANIFEST_FIXES.items():
    p = pull(rel)
    doc = json.load(open(p))
    before, after = REDACTED[target][1], REDACTED[target][2]
    if doc.get("output_sha256") == before:
        doc["output_sha256"] = after
        print(f"  {rel}: output_sha256 moved to the shipped bytes")
    elif doc.get("output_sha256") == after:
        print(f"  {rel}: output_sha256 already current")
    else:
        print(f"ABORT: {rel} output_sha256 is neither the pre- nor the post-redaction value")
        raise SystemExit(2)
    doc["redaction"] = redaction_block(target)
    if "partition" in doc and isinstance(doc["partition"], dict):
        doc["partition"]["source_corpus_sha256_note"] = (
            "the pre-redaction digest of the source corpus, which is what this partition was cut "
            "from; see redaction")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
    changed[rel] = p

for rel in TOUCH_ONLY:
    p = pull(rel)
    doc = json.load(open(p))
    doc["redaction"] = {
        "applied_to_source_corpus": True,
        "kind": "post-hoc credential redaction",
        "source_corpus": "corpora/terminalbench/cases.jsonl",
        "sha256_before_redaction": REDACTED["corpora/terminalbench/cases.jsonl"][1],
        "sha256_after_redaction": REDACTED["corpora/terminalbench/cases.jsonl"][2],
        "length_preserving": True,
        "this_file_unchanged": True,
        "note": ("the digest recorded here for the source corpus is the pre-redaction one, which "
                 "is the bytes this split was cut from. " + NOTE),
    }
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
    changed[rel] = p
    print(f"  {rel}: redaction recorded, file contents unchanged")

# ------------------------------------------------------------------------------- the ledger
ledger = {
    "kind": "defenseclaw-corpora-redaction-ledger",
    "schema_version": "1",
    "summary": ("A live-looking credential was removed from four corpus files. The replacement is "
                "length-preserving and drawn from the same character class, so file sizes are "
                "unchanged and the rows still exercise credential detection. Only digests moved."),
    "reproducing": NOTE,
    "placeholder_length_bytes": len(PLACEHOLDER),
    "unrelated_placeholder_left_in_place": (
        "HuggingFace's own documentation placeholder also appears in these files and was left "
        "alone; it is not a credential."),
    "files_in_this_dataset": [
        {"path": r, "occurrences_replaced": o,
         "sha256_before_redaction": b, "sha256_after_redaction": a}
        for r, (o, b, a) in sorted(REDACTED.items())],
    "files_redacted_but_not_in_this_dataset": [
        {"path": r, "occurrences_replaced": o,
         "sha256_before_redaction": b, "sha256_after_redaction": a,
         "note": "local evaluation input; never uploaded to this dataset"}
        for r, (o, b, a) in sorted(NOT_IN_DATASET.items())],
    "records_deliberately_left_unchanged": (
        "Run metas, scorecards, plan files and logs outside this dataset still record the "
        "pre-redaction digest of the input they were produced against. That is a true statement "
        "about which bytes were scored, and rewriting it would make the predictions "
        "unverifiable. This ledger is the mapping between the two."),
    "scored_corpora_unaffected": {
        "s2": "39f2c1df2369952a0525cc4c5575f4bdb590fb3ca8c1bc6805cf4f376c1adbf7",
        "s3": "0ccbc08fb408ffefc89e051c585cfe22433b1ed4c9714f60cc0f7e242969fa03",
        "note": "neither scored corpus contained the string, so every published figure stands",
    },
}
lp = os.path.join(WORK, "REDACTIONS.json")
with open(lp, "w", encoding="utf-8") as fh:
    json.dump(ledger, fh, indent=2, sort_keys=True)
    fh.write("\n")
changed["REDACTIONS.json"] = lp
print(f"  REDACTIONS.json: ledger written, {os.path.getsize(lp):,} bytes")

# ------------------------------------------------------- MANIFEST.json, SHA256SUMS, README.md
man_p, sums_p, readme_p = pull("MANIFEST.json"), pull("SHA256SUMS"), pull("README.md")
man = json.load(open(man_p))
rows: dict[str, str] = {}
for ln in open(sums_p, encoding="utf-8"):
    ln = ln.rstrip("\n")
    if ln.strip():
        h, pth = ln.split(None, 1)
        rows[pth.strip()] = h

new_digests: dict[str, tuple[str, int]] = {}
for rel in REDACTED:
    src = os.path.join(STAGE_SRC, rel)
    new_digests[rel] = (sha256(src), os.path.getsize(src))
for rel, p in changed.items():
    new_digests[rel] = (sha256(p), os.path.getsize(p))

bytes_before = man["total_bytes"]
for rel, (h, size) in new_digests.items():
    e = man["files"].get(rel, {})
    e = {**e, "bytes": size, "sha256": h}
    man["files"][rel] = e
    rows[rel] = h
man["files"] = {k: man["files"][k] for k in sorted(man["files"])}
man["file_count"] = len(man["files"])
man["total_bytes"] = sum(v["bytes"] for v in man["files"].values())
man["redactions"] = {"ledger": "REDACTIONS.json",
                     "files": sorted(REDACTED), "length_preserving": True}
with open(man_p, "w", encoding="utf-8") as fh:
    json.dump(man, fh, indent=1, sort_keys=True)
    fh.write("\n")
with open(sums_p, "w", encoding="utf-8") as fh:
    for pth in sorted(rows):
        fh.write(f"{rows[pth]}  {pth}\n")
print(f"\nMANIFEST.json : {man['file_count']} files, {man['total_bytes']:,} bytes "
      f"(was {bytes_before:,})")
print(f"SHA256SUMS    : {len(rows)} lines")
assert set(rows) == set(man["files"]), "SHA256SUMS and MANIFEST disagree"

# README: update the Contents rows for every path whose digest moved, and add a section
rd = open(readme_p, encoding="utf-8").read()
orig = rd
for rel, (h, size) in new_digests.items():
    pat = re.compile(r"^\| `" + re.escape(rel) + r"` \| [\d,]+ \| ([^|]*)\| `[0-9a-f]{64}` \|$",
                     re.M)
    m = pat.search(rd)
    if m:
        rd = pat.sub(f"| `{rel}` | {size:,} | {m.group(1)}| `{h}` |", rd, count=1)
    else:
        anchor = "| `excluded/intent-ablation/cases.manifest.json` |"
        rd = rd.replace(anchor, f"| `{rel}` | {size:,} | - | `{h}` |\n{anchor}", 1)
if "## Post-hoc credential redaction" not in rd:
    sec = (
        "## Post-hoc credential redaction\n"
        "\n"
        "A 37-byte string matching the HuggingFace user access token format was found in four\n"
        "corpus files and removed. The replacement is the same length and drawn from the same\n"
        "character class, so **file sizes are unchanged and the rows still exercise credential\n"
        "detection**. Only digests moved. `REDACTIONS.json` carries the full mapping.\n"
        "\n"
        "| file | occurrences | sha256 before | sha256 after |\n"
        "|---|---|---|---|\n"
        + "".join(f"| `{r}` | {o} | `{b}` | `{a}` |\n"
                 for r, (o, b, a) in sorted(REDACTED.items()))
        + "".join(f"| `{r}` (not in this dataset) | {o} | `{b}` | `{a}` |\n"
                 for r, (o, b, a) in sorted(NOT_IN_DATASET.items()))
        + "\n"
        "**Reproducing a prediction.** The settled prediction bodies were produced against the\n"
        "pre-redaction input, so a row's `context_sha256` reproduces from the *before* digest and\n"
        "not from the file shipped here. No prediction body, run meta, scorecard or log was\n"
        "modified. Run records elsewhere in the estate still carry the pre-redaction digest,\n"
        "which is a true statement about which bytes were scored; `REDACTIONS.json` is the\n"
        "mapping between the two.\n"
        "\n"
        "`source_corpus_sha256` in the partition manifests is left at the pre-redaction value,\n"
        "because it says which bytes the partition was cut from.\n"
        "\n"
        "HuggingFace's own documentation placeholder also appears in these files. It is not a\n"
        "credential and was left in place.\n"
        "\n"
        "The two scored corpora never contained the string: `s2` stays\n"
        "`39f2c1df2369952a0525cc4c5575f4bdb590fb3ca8c1bc6805cf4f376c1adbf7` and `s3` stays\n"
        "`0ccbc08fb408ffefc89e051c585cfe22433b1ed4c9714f60cc0f7e242969fa03`, so every published\n"
        "figure keyed to them stands.\n"
        "\n")
    rd = rd.replace("## What is not here", sec + "## What is not here", 1)
if rd == orig:
    print("ABORT: README unchanged.")
    raise SystemExit(2)
open(readme_p, "w", encoding="utf-8").write(rd)
print("README.md     : Contents rows updated and a redaction section added")

# ------------------------------------------------------------------------------- one commit
ops = [CommitOperationAdd(path_in_repo=rel, path_or_fileobj=os.path.join(STAGE_SRC, rel))
       for rel in sorted(REDACTED)]
ops += [CommitOperationAdd(path_in_repo=rel, path_or_fileobj=p)
        for rel, p in sorted(changed.items())]
ops += [CommitOperationAdd(path_in_repo="MANIFEST.json", path_or_fileobj=man_p),
        CommitOperationAdd(path_in_repo="SHA256SUMS", path_or_fileobj=sums_p),
        CommitOperationAdd(path_in_repo="README.md", path_or_fileobj=readme_p)]

if "--dry-run" in sys.argv:
    print("\nDRY RUN. would commit:")
    for o in ops:
        print("   ", o.path_in_repo)
    raise SystemExit(0)

commit = api.create_commit(
    repo_id=DS, repo_type="dataset", operations=ops,
    commit_message="Redact a credential-shaped string from the terminalbench corpora",
    commit_description=(
        "A 37-byte string matching the HuggingFace user access token format appeared in four "
        "corpus files and was replaced with a same-length placeholder of the same character "
        "class. File sizes are unchanged and the rows still exercise credential detection; only "
        f"digests moved. Three of the four files are in this dataset:\n\n"
        + "".join(f"- {r}: {o} occurrences, {b[:12]} -> {a[:12]}\n"
                 for r, (o, b, a) in sorted(REDACTED.items()))
        + "\nThe fourth, s1-n1000/terminalbench-context-cases.jsonl, is a local evaluation input "
        "and is not in this dataset.\n\n"
        "REDACTIONS.json is added as the ledger and carries both digests for every file. Each "
        "affected manifest gains a redaction block; output_sha256 moves to the shipped bytes and "
        "source_corpus_sha256 stays at the pre-redaction value, because it says which bytes a "
        "partition was cut from.\n\n"
        "Settled prediction bodies were produced against the pre-redaction input, so a row's "
        "context_sha256 reproduces from the before digest. No prediction body, run meta, "
        "scorecard or log was modified, and run records elsewhere still carry the pre-redaction "
        "digest as a true record of what was scored.\n\n"
        "Neither scored corpus contained the string, so every published figure keyed to s2 or s3 "
        "stands. The archive stays private."))
print(f"\ncommit: {getattr(commit, 'oid', commit)}")

after_info = api.dataset_info(DS)
print(f"privacy AFTER  : private={after_info.private!r}  sha={after_info.sha}")
if after_info.private is not PRIV_BEFORE:
    print(f"ABORT: privacy changed {PRIV_BEFORE!r} -> {after_info.private!r}")
    raise SystemExit(2)
print("privacy unchanged")
