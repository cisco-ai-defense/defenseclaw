#!/usr/bin/env python3
"""Create the SLM tool-call security Space and upload the payload.

Copied from benchmarks/system_one/reproduce/08-site-build/publish.py. The five gates and their
ordering are unchanged; the repository id, the payload path and the commit text are this
programme's.

Gates, in order. Any failure aborts before the next step:
  1. the payload guard must have passed (re-run here, not trusted from earlier)
  2. the post-build verifier must pass
  3. the repo's visibility is READ and recorded. This script never sets it, in either
     direction: `create_repo` is only reached when the Space does not exist yet, and the
     upload call passes no visibility argument.
  4. the upload happens
  5. the visibility is read again and must be IDENTICAL to step 3. A change either way
     aborts, because nothing here is allowed to move a repo between public and private.
     The repository's file list is also compared with the payload, because `upload_folder`
     adds and replaces without deleting: a file the build never produced can survive from an
     earlier revision or from the SDK template that Space creation writes, and it would be
     published without the payload guard ever having scanned it. Anything outside the payload
     is listed by name. `.gitattributes` is repository-side configuration and is expected.

No credential is ever read into a printable variable: huggingface_hub reads the stored token
itself and nothing here touches it.
"""
from __future__ import annotations

import os
import subprocess
import sys

from huggingface_hub import HfApi

SRC = os.path.dirname(os.path.abspath(__file__))
SITE = os.environ.get("SLM_SPACE_OUT", os.path.join(SRC, "site"))
REPO = os.environ.get("SLM_SPACE_REPO", "Vineethsain/defenseclaw-slm-toolcall")
PY = os.environ.get("SLM_PY", sys.executable)


def step(label):
    print("\n" + "=" * 74)
    print(label)
    print("=" * 74)


def run_gate(script):
    r = subprocess.run([PY, os.path.join(SRC, script), SITE], capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    if r.stderr.strip():
        sys.stdout.write(r.stderr)
    if r.returncode != 0:
        print(f"ABORT: {script} exited {r.returncode}")
        raise SystemExit(1)


def read_visibility(api, when):
    info = api.space_info(REPO)
    state = "private" if info.private else "PUBLIC"
    print(f"  space_info().private {when}: {info.private!r}  ({state})")
    return info


step("GATE 1 - payload guard")
run_gate("guard.py")

step("GATE 2 - structure, links, layout")
run_gate("verify.py")

api = HfApi()
me = api.whoami()
print(f"\nauthenticated as: {me.get('name')}")

step("GATE 3 - read the Space's visibility, and do not touch it")
existing = None
try:
    existing = api.space_info(REPO)
except Exception:  # noqa: BLE001
    existing = None

if existing is None:
    # a Space this script creates starts private; only the owner can widen it
    url = api.create_repo(repo_id=REPO, repo_type="space", space_sdk="static",
                          private=True, exist_ok=False)
    print(f"  created (private): {url}")
else:
    print("  already exists; this script will not change its visibility")
before = read_visibility(api, "before upload")
if before.private is not True:
    print("  NOTE: this Space is PUBLIC. The payload guard is the control that matters here,")
    print("        and it passed in GATE 1. Nothing in this script makes a repo public or")
    print("        private; the visibility is the owner's setting and is left exactly as found.")

step("GATE 4 - upload")
files = []
for root, _d, names in os.walk(SITE):
    for n in sorted(names):
        p = os.path.join(root, n)
        files.append((os.path.relpath(p, SITE), os.path.getsize(p)))
for rel, size in sorted(files):
    print(f"  {rel:28s} {size:>8,} bytes")
print(f"  {'TOTAL':28s} {sum(s for _, s in files):>8,} bytes in {len(files)} files")

commit = api.upload_folder(
    repo_id=REPO,
    repo_type="space",
    folder_path=SITE,
    # Pages cut from the site must leave the Space in the same commit. A matching file that is
    # also in the payload is updated, not deleted, so only orphans go.
    delete_patterns=["*.html", "_wordcount.json"],
    commit_message="Cut the site to five pages, state the answer first, and correct the figures "
                   "the review found wrong",
    commit_description=(
        "The same artifacts and the same corpus s2 at cases_sha256 "
        "39f2c1df2369952a0525cc4c5575f4bdb590fb3ca8c1bc6805cf4f376c1adbf7.\n\n"
        "STRUCTURE\n"
        "Eleven pages become five: Answer, At the budget, Ranking and diagnostics, Data and "
        "models, Method and reproduce. sizes, baselines, roster, footprint, glossary and "
        "reproduce are folded in and deleted from the Space in this commit. The H1 states the "
        "answer. The leaderboard at the common block-FPR budget is the ranking that answers the "
        "question; AUC order is a diagnostic. The second corpus's grade-mix caveat is stated once, "
        "on Data and models.\n\n"
        "CORRECTIONS\n"
        "Figures that still used the retracted unweighted length-controlled estimator now use the "
        "published pair-weighted pooled one: DeBERTa 0.8347, controls 0.4876 and 0.3890. 0.3890 is "
        "below the chance band, so the leakage gate is reported as not met. Also corrected: the "
        "double-budget false-block count (26), a throughput attributed to the wrong model, the "
        "memory statement, the overlap framing, the grade B definition, the length-cue scalars, "
        "and templated counts that rendered as zero. Each is pinned by a build assertion "
        "(2,251, 0 mismatches) and the wrong phrasings are retired in verify.py."
    ),
)
print(f"\n  commit: {getattr(commit, 'oid', commit)}")

step("GATE 5 - visibility unchanged after upload")
info = read_visibility(api, "after upload")
if info.private is not before.private:
    print(f"ABORT: visibility changed during the upload: {before.private!r} -> "
          f"{info.private!r}. Nothing here should have done that.")
    raise SystemExit(2)
print("  visibility unchanged by this upload")

# upload_folder does not delete, so the repository can hold a file the payload does not.
# Hugging Face's static-SDK template writes index.html and style.css at creation; the upload
# replaces index.html and leaves style.css, which is how an unguarded file reaches a published
# Space. Anything here that the guard never saw is named.
REPO_SIDE = {".gitattributes"}
payload = {rel for rel, _ in files}
listed_now = set(api.list_repo_files(REPO, repo_type="space"))
orphans = sorted(listed_now - payload - REPO_SIDE)
print(f"  payload files      : {len(payload)}")
print(f"  repository files   : {len(listed_now)}")
if orphans:
    print(f"  ORPHANS: {len(orphans)} file(s) in the repository that this payload did not "
          f"produce and the guard never scanned:")
    for o in orphans:
        print(f"    {o}")
    print("  Review each one and delete it if it is not meant to be published. This script does "
          "not delete, because deciding what belongs is not its job.")
else:
    print("  orphans            : 0; the repository holds exactly the payload plus "
          f"{', '.join(sorted(REPO_SIDE))}")

print("\n" + "=" * 74)
print("RESULT")
print("=" * 74)
print(f"  space id     : {REPO}")
print(f"  url          : https://huggingface.co/spaces/{REPO}")
print(f"  sdk          : {info.sdk}")
print(f"  private      : {info.private}")
print(f"  revision     : {info.sha}")
print(f"  last modified: {info.last_modified}")
listed = api.list_repo_files(REPO, repo_type="space")
print(f"  files in repo: {len(listed)}")
for f in sorted(listed):
    print(f"    {f}")
