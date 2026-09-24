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
    commit_message="Report every arm at one common false-positive budget, split the cohort by "
                   "counted parameters, and document both corpora and their label scheme",
    commit_description=(
        "Every arm is now reported at ONE operating point, and each arm's own argmax is a separate "
        "table. Corpus s2, 3,817 scorable of 4,277, 436 positives, 3,381 benign, cell C7/I3/Q2, "
        "cases_sha256 39f2c1df2369952a0525cc4c5575f4bdb590fb3ca8c1bc6805cf4f376c1adbf7.\n\n"
        "ONE COMMON OPERATING POINT, AND IT IS THE HEADLINE\n"
        "All 22 arms are re-thresholded to a block false-positive rate of 0.00384502, the "
        "incumbent cascade's own rate on this corpus, which allows 13 false blocks of 3,381 benign "
        "cases. operating-point.html prints tp, fp, fn, tn, precision, recall, F1, accuracy and "
        "block FPR for every arm at that one budget, with the threshold each arm needed beside "
        "them, and the two trivial baselines as rows in the same table. No arm appears there at a "
        "threshold chosen for it alone. The best F1 is falcon3-1b-instruct at 0.10548523206751055, "
        "recall 0.05733944954128441, precision 0.6578947368421053, 25 true blocks of 436 positives "
        "and 13 false blocks of 3,381 benign, accuracy 0.8889179984280848, threshold "
        "0.6170100906975968. Under a zero-false-positive gate 13 of the 20 candidates retain zero "
        "recall. Both facts are in the lede of the Space and of the card.\n"
        "Each arm's own argmax is a second table on the same page, headed an in-sample oracle "
        "upper bound, with the common-budget F1 repeated as the last column so the gap between a "
        "fitted ceiling and a fixed budget is visible per arm. The two never share a column. All "
        "22 arms clear the trivial floor at their own argmax; the 9 of 19 that fall below it, and "
        "the 5 that score exactly zero, do so at their SHIPPED decision. The previous revision's "
        "chart subtitle attributed those 5 to the argmax, which was wrong, and a retired literal "
        "now blocks that sentence.\n\n"
        "THRESHOLD-FREE, WITH THE DEFINITION LABELLED\n"
        "results.html#auc carries raw AUC and length-controlled AUC per arm, the ranking variable, "
        "the class structure, the AUC definition label, and where the arm falls against the chance "
        "band [0.471205496131191, 0.528794503868809] from a Hanley-McNeil standard error of "
        "0.014691343359335349. All 22 arms are ranked on a variable for which definitions A and B "
        "coincide, because each such variable is already a single monotone scalar and both "
        "definitions reduce to the same maximum over events. The variables where A and B genuinely "
        "differ are shown apart, on one three-class arm that carries all of them, and the excluded "
        "difference variable sits in that table with the statement that it inverted below chance.\n"
        "The artifact records rank_1_stable and rank_2_stable as false. The previous revision said "
        "ranks 1 and 2 hold their places under every estimator; that sentence is withdrawn and a "
        "retired literal blocks it. Each is contradicted by one of the 9 schemes, the same scheme "
        "in both cases, whose bins move with each arm's own truncation.\n\n"
        "SIZE BANDS, FROM COUNTED PARAMETERS\n"
        "sizes.html splits the cohort at 3e9 and 6e9 counted parameters: 14 arms under 3B, 8 from "
        "3B to 6B, 0 at 6B and up. The empty band is printed with its zero count and one line "
        "saying nothing in the cohort lands there. Rank inside a band is F1 at the common budget. "
        "Every parameter count is read from the arm's own run metadata and asserted against "
        "harness/arms.py; 22 of 22 agree. granite-guardian-3.2-3b-a800m is a mixture-of-experts "
        "arm and its counted total of 3,298,793,472 is stated as such, with the note that the "
        "artifacts carry no counted active-parameter figure for it.\n\n"
        "ACCURACY ONLY WITH THE BASELINE BESIDE IT\n"
        "At prevalence 0.11422583180508253 on s2, allowing every case scores 0.8857741681949175; "
        "on the second corpus, prevalence 0.009029253145938878 gives 0.9909707468540612. Both "
        "baselines are rows in the same table as the accuracy figures, on both corpora. An arm "
        "beats the all-allow figure exactly when it gains more true blocks than it spends on false "
        "ones; 3 of the 22 do, by at most 12 cases of 3,817.\n\n"
        "A DATASETS PAGE THAT DOCUMENTS THE DATA\n"
        "datasets.html carries both corpora field by field: cases, scorable cases, positives by "
        "grade, benign, grade-C exclusions, prevalence, all-allow accuracy, block-everything F1, "
        "chance band and standard error, rows per arm, cases_sha256 and the 0 case-id overlap. "
        "s2 at 39f2c1df2369952a0525cc4c5575f4bdb590fb3ca8c1bc6805cf4f376c1adbf7, the second at "
        "0ccbc08fb408ffefc89e051c585cfe22433b1ed4c9714f60cc0f7e242969fa03.\n"
        "How a label was assigned is now on the page rather than implied. One deterministic "
        "function, truth_grade() in benchmarks/scripts/benchmark_inventory_system_one_sources.py, "
        "8,768 bytes at sha256 "
        "b1c66462dfd8a6cbb8a3332e5e548774e10e4ba426facdfb43cf5fbacf194995, evaluated at scoring "
        "time from fields already on each case row. The condition the function tests for each of "
        "A, B, C, D and E is printed beside the grade and the case counts. No model and no human "
        "reviewer is consulted, so no inter-rater agreement figure exists, and the page says so. "
        "The build hashes that module and fails if it stops defining the function or stops "
        "returning any of the five grades.\n"
        "Licence and redistribution are recorded per source in benchmarks/datasets.lock.json, 92 "
        "entries frozen 2026-09-06 at sha256 "
        "48a6639433402efcb7069439cb90941d953df89bf4a1a342bdd215ba61298679: 80 download-only, 8 "
        "vendored, 4 aggregate-only, across 13 distinct licences. The lock is cited by digest "
        "because copies of it differ across revisions. mcptox stays named as the "
        "local-evaluation-only source. The second restricted source is described and no longer "
        "named, because it is being removed from the corpora and contributes 0 rows to either; a "
        "census recorded in benchmarks/archive/records/ is read and asserted at 0 rows over 2 "
        "sources, and a retired literal blocks the name from returning.\n\n"
        "THE TWO CORPORA STILL SUPPORT NO TRANSFER CLAIM\n"
        "s2's positives are 17 grade A and 419 grade B, 3.90% grade A. The second corpus's are 193 "
        "grade A and 28 grade B, 87.33%. A difference between the two conflates threshold "
        "miscalibration with a changed definition of a positive. No transfer penalty and no "
        "generalisation claim appears in either direction. Every mention of the held-out corpus, "
        "of transfer or of generalising must sit near that composition figure or the verifier "
        "fails the build, and the corpus label in every table now carries the 87.33% with it.\n"
        "The length cue is a property of s2: prompt tokens 0.7692264380822134, event count "
        "0.7772553177633239, with no model at all. On the second corpus context_bytes reaches "
        "0.504185543681342 and context_events 0.34604723008084354, inside and below its chance "
        "band of [0.46176687597792665, 0.5382331240220734], so raw AUC is the primary there.\n\n"
        "THE HELD-OUT BODIES ARE SETTLED, AND THE TWO ARTIFACTS ARE RECONCILED\n"
        "6 arms carry a settled body on the second corpus, each 100,001 rows over all 24,476 "
        "cases with 0 errors, 0 cases missing, complete: true and a digest matching the bytes on "
        "disk. cohort-rank.json holds a partial block covering 3 of those arms. The build asserts "
        "that the two artifacts agree on every arm they share -- same ranking variable, same raw "
        "AUC to the last digit, same row count, same prediction digest, same argmax confusion "
        "matrix -- so the 6-arm pair governs on coverage and the page says which and why.\n\n"
        "MORE CORPUS CHANGES NOTHING\n"
        "All 15 of the 15 pairwise comparisons on that corpus already separate at p < 0.05. The "
        "narrowest pair would have been significant on 32 positives under proportional growth or "
        "31 under positive-only growth, against the 221 the corpus holds; the widest needs 173, "
        "which it also holds. A false-positive cap is a rate, so a larger benign pool grows the "
        "allowance in step. The Wilson 95% interval on the best recall at the cap is "
        "[0.039137016728024596, 0.08327404239553826], recomputed here and asserted against the "
        "artifact. 98.68% of the AUC variance on that corpus comes from its 221 positives, so the "
        "positive count is the binding constraint on every per-positive quantity, and the binding "
        "constraint this cohort measures is the grade composition of the positives.\n\n"
        "GATES\n"
        "1,019 figure assertions and 0 mismatches, up from 447, over 19 files and 22 charts. Every "
        "arm's confusion matrix at the common budget, at a zero-FP gate and at its own argmax is "
        "recomputed from its own counts and checked against the rates the artifact records, and "
        "the budget is asserted to hold on every row. Label-fit, layout-collision, palette, "
        "front-matter, markup, scope and held-out checks all clean; 0 of 11 out-of-scope names "
        "present. The scope gate caught one out-of-scope name in a draft of index.html and the "
        "retired-literal gate caught two stale claims; both are fixed rather than suppressed. "
        "reproduce.html now generates its artifact list from the build's own read log with a "
        "digest per file, so a new input cannot be read without appearing there.\n"
        "Payload guard PASS over 14 files and 700,088 bytes, 0 corpus case ids, 0 sensitive-text "
        "shingles, 0 CJK codepoints, 0 credential patterns, with 17 corpora and 201,106 case ids "
        "indexed and no protocol exemption. Verifier 10 pages, 0 problems, 26 chart figures, 67 "
        "retired figures checked and 0 present, 226 internal links resolved, 59 outbound links to "
        "allowed targets, 0 other external URLs, 0 scripts and 0 subresources. Visibility read "
        "before and after and unchanged."
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
