#!/usr/bin/env python3
"""Create the private static Space and upload the payload.

Gates, in order. Any failure aborts before the next step:
  1. the payload guard must have passed (re-run here, not trusted from earlier)
  2. the post-build verifier must pass
  3. the repo's visibility is READ and recorded. This script never sets it, in either
     direction: `create_repo` is only reached when the Space does not exist yet, and the
     upload call passes no visibility argument.
  4. the upload happens
  5. the visibility is read again and must be IDENTICAL to step 3. A change either way
     aborts, because nothing here is allowed to move a repo between public and private.

No credential is ever read into a printable variable: huggingface_hub reads the stored token
itself and nothing here touches it.
"""
from __future__ import annotations

import os
import subprocess
import sys

from huggingface_hub import HfApi

SITE = os.environ.get("SPACE_SITE", "$WORK/.system-one-space-build/site")
SRC = os.path.dirname(os.path.abspath(__file__))
REPO = "Vineethsain/defenseclaw-system-one"
PY = os.environ.get("SPACE_PY", "$WORK/.system-one-venv/bin/python")


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

payload_files = len(files)
payload_bytes = sum(s for _, s in files)

commit = api.upload_folder(
    repo_id=REPO,
    repo_type="space",
    folder_path=SITE,
    # Pages cut from the site must leave the Space in the same commit. A matching file that is
    # also in the payload is updated, not deleted, so only orphans go.
    delete_patterns=["*.html", "_wordcount.json"],
    commit_message="Cut the site to six pages, lead with the shared-budget ranking, and state "
                   "one recommended cascade",
    commit_description=(
        f"The payload is {payload_bytes:,} bytes over {payload_files} files.\n\n"
        "STRUCTURE\n"
        "Fourteen pages become six: Which model, Deploy, Risks, Intent, Method & data, Reproduce. "
        "compare, examples, experiments, glossary, prompts, recommendations and the five finding "
        "pages are folded in and deleted from the Space in this commit. Per-figure provenance "
        "tooltips are removed; sources are in each figure caption and on Reproduce.\n\n"
        "HEADLINE\n"
        "Every model is ranked at one shared block false-positive budget, 0.00384502 (13 false "
        "blocks of 3,381), so shipped block-only F1 is a column rather than a second ranking. The "
        "recommended stack is stated once, identically on every page: rules -> OpenJev -> Gemma 4 "
        "with two-sided routing at 0.30 and escalate-on-confirm, block-only F1 0.75173 at block "
        "FPR 0.00414. 0.73773 is the same stack with today's short-circuit on a rule confirm.\n\n"
        "CORRECTIONS\n"
        "Every figure is shown at reading precision with its exact value one click away. Also "
        "fixed: the recommendation count, the question-format spread, the recall-at-cap variable, "
        "the provider-spend token total, the latency unit, and the cache-tuning workloads."
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
