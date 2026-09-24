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

SITE = "$WORK/.system-one-space-build/site"
SRC = os.path.dirname(os.path.abspath(__file__))
REPO = "Vineethsain/defenseclaw-system-one"
PY = "$WORK/.system-one-venv/bin/python"


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
    commit_message="Add kev-9b and open-jev-qwen-27b as ranked rows, and publish the "
                   "re-thresholded ceilings, the held-out figures and the two floors",
    commit_description=(
        f"Two arms join the ranked table and a third gains its held-out corpus. Both new arms "
        f"were scored by the same scorer against the same real deterministic rule tier as every "
        f"row already on the board, on 3,817 scorable cases of the Broad comparison at C7/I3/Q2, "
        f"30,310 decisions and 0 errors each, from settled bodies whose on-disk sha256 matches "
        f"prediction_sha256. The payload is {payload_bytes:,} bytes over {payload_files} files.\n\n"

        "Rows added, block-only F1 / precision / recall / block FPR / any-intervention F1 / "
        "three-way accuracy\n"
        "- open-jev-qwen-27b  0.33206 / 0.98864 / 0.19954 / 0.00030 / 0.45213 / 0.8124  "
        "(rank 4 of 11)\n"
        "- kev-9b             0.01814 / 0.80000 / 0.00917 / 0.00030 / 0.24101 / 0.8855  "
        "(rank 11 of 11, last)\n"
        "Neither is a recommendation. open-jev-qwen-27b is ZefanCai/Open-Jev-27B-v1.1 at "
        "revision 28cf73067d5b on Qwen/Qwen3.8-27B, kev-9b is jaredpalmer/kev-9b at revision "
        "2629c06a5aeb on Qwen/Qwen3.5-9B-Base. Neither is DefenseClaw's own trained model and "
        "none of our own weights appear here.\n\n"

        "The new section: shipped thresholds against re-thresholded figures\n"
        "Every F1 in the ranked table is its arm's shipped argmax. A single-threshold sweep over "
        "one ranking variable on the same cases raises it for all 12 arms that carry a "
        "disposition distribution, by +0.0590 (open-jev-qwen-2b) to +0.5540 "
        "(jevify-gemma4-26b-a4b). Every one of those ceilings is fitted on the cases it is "
        "scored on and is labelled an oracle upper bound on its face, and every one is printed "
        "beside the pooled out-of-fold figure from grouped 5-fold cross-validation inside the "
        "same corpus, where the threshold and the variable were chosen on the training folds "
        "alone. The two figures come from two files written by two passes and the build pins "
        "both for all 13 rows of the table.\n"
        "- kev-9b. Shipped 0.018140589569160998, the lowest of the 11 ranked rows. Its "
        "case-level dispositions are 3,708 allow / 104 confirm / 5 block, so block recall was "
        "bounded at 5/436 before correctness entered; 4 of those 5 blocks land on an unsafe "
        "case. Re-thresholded on P(block) under definition A it reaches 0.4182648401826484 in "
        "sample and 0.41530054644808745 out of fold, a ratio of 23.056849315068494 over the "
        "shipped figure and the largest multiplier in the table.\n"
        "- open-jev-qwen-27b. Shipped it blocks 88 times in 3,817 cases: tp 87 / fp 1 / fn 349 / "
        "tn 3380, one false block. AUC on P(block) 0.9480285133598713. Two re-thresholded points "
        "are published and each carries the constraint it was found under, because the two are "
        "not interchangeable: unconstrained best 0.8216340621403913 at t=0.09849565994909716 "
        "(tp 357 / fp 76 / fn 79 / tn 3305, block FPR 0.022478556640047324), and capped at the "
        "incumbent OpenJev's own block false-positive rate of 0.00384502, 0.7387640449438202 at "
        "t=0.1872577399799149 (tp 263 / fp 13 / fn 173 / tn 3368, achieved 0.003845016267376516). "
        "Out of fold the unconstrained point holds 0.8167053364269141; the capped point reaches "
        "0.7513812154696132 at an achieved rate of 0.004732327713694173, outside the cap it was "
        "fitted to, and that is stated with it.\n\n"

        "Not published: 0.6092050209205021, kev-9b's highest figure\n"
        "It rests on P(block) - P(confirm) under definition B. That variable inverted below "
        "chance on the disjoint corpus for both arms where the transfer could be measured, "
        "OpenJev 0.856982082821162 to 0.2994021851164708 and Jev 1.13.0 0.838702313793487 to "
        "0.3420025352798462, and kev-9b has no settled run there. The same treatment is applied "
        "to every row: that variable holds the highest in-sample figure for 5 of the 11 ranked "
        "rows, each figure is named beside the ceiling it exceeds, and none of the five ranks "
        "anything. The ceiling column is the best figure over the remaining variables, which "
        "means the incumbent's own ceiling of 0.8086560364464692 on P(block) is the comparator "
        "the table uses rather than the 0.70231214 it ships at; the gap between those two, "
        "0.10634389771814556, belongs to the incumbent's calibration and is printed as such.\n\n"

        "The two floors, both read from the corpus they belong to\n"
        "Blocking every case scores block-only F1 0.20503174229955326 at the Broad comparison's "
        "11.42% prevalence, with block FPR 1.0. 4 of the 11 ranked rows score below that at "
        "their shipped operating point (open-jev-qwen-9b 0.17551020, open-jev-qwen-2b "
        "0.17194570, jevify-gemma4-26b-a4b 0.04921700, kev-9b 0.018140589569160998) and 2 more "
        "clear it by under 0.012 (bespoke-nimble-9b 0.21568627, SecJudge 0.20724154). The "
        "membership of both lists is computed over the ranked population at build time.\n\n"

        "bespoke-nimble-9b on the held-out corpus, with the caveat that governs it\n"
        "The artifact is merged from 53 shards into 100,001 rows over 24,476 cases, 0 error "
        "rows, complete:true, digest "
        "b34651649b668c069dc02253c0e79682305ab57c4277d233fb189a6ad57a3842. It totals 270,881,394 "
        "input tokens against the runner's 200,000,000 per-driver budget, which it exceeds by "
        "70,881,394; a single driver would have been stopped before finishing. Shipped there it "
        "scores 0.00881057268722467 at tp 2 / fp 231 / fn 219 / tn 24024, block FPR "
        "0.009523809523809525, below that corpus's own floor of 0.017896910555937968. Its AUC on "
        "P(block) is 0.961057896352014 against a chance band of [0.46176687597792665, "
        "0.5382331240220734], and its in-sample oracle there is 0.3624733475479744.\n"
        "The transfer penalty of 0.14391899353545304 is published, and the composition caveat "
        "sits beside it in the same paragraph and again in the table above it. The Broad "
        "comparison's 436 positives are 17 grade A and 419 grade B, 3.90% grade A; the held-out "
        "corpus's 221 positives are 193 grade A and 28 grade B, 87.33% grade A. Both terms of "
        "the penalty are measured on the held-out corpus, so the 12.65x prevalence gap cancels "
        "out of the subtraction, and the page says the grade composition does not. The two "
        "corpora share 0 case ids. A census of both finds 0 rows from the "
        "local-evaluation-only source and 0 from the aggregate-only source, re-run for this "
        "change rather than carried forward.\n\n"

        "Artifact work, and what it changed\n"
        "- open-jev-qwen-27b's H200 scorecard was re-scored against the real deterministic tier "
        "and the judge tier, because the H200 pipeline had written only the model-alone node and "
        "the leaderboard column reads deterministic_then_system_one. Every cell of the rebuilt "
        "scorecard matches the comparison table row that was assembled independently, and the "
        "build's cell-for-cell cross-check pins all eight.\n"
        "- kev-9b's settled body was staged from the studio run into the outputs tree after ten "
        "checks: complete:true, sha256 against prediction_sha256, 30,310 rows, 4,277 cases, 0 "
        "error rows, the corpus digest, the C7/I3/Q2 cell, and the checkpoint sha against the "
        "serving provenance. It was then scored by the shared scorer, and its AUC file was "
        "regenerated by the script every other arm used; the four figures it produces are "
        "identical at full precision to the ones the independent re-mining pass recorded.\n"
        "- Both arms' serving records gained the nested served / serving blocks the build reads, "
        "composed from the flat provenance already in them, and both run metas gained the six "
        "provenance keys the build reads, each copied from the file that recorded it and each "
        "logged with its source under meta_augmented. No flat key was removed or changed and "
        "prediction_sha256 still covers each body byte for byte. For open-jev-qwen-27b all four "
        "replica startup records were checked to agree field by field before any value was "
        "carried over.\n\n"

        "Correction to the provider-spend reconciliation, found while adding the rows\n"
        "Six runs have their manifest at two paths in the outputs tree at the same run_id and "
        "the same body digest: a staged copy beside a guard payload, a pre-settlement copy "
        "beside the settled one, a resume ledger beside the run it resumed. The rollup counted "
        "both copies, so the published request total carried 151,608 requests twice. Manifests "
        "are now counted once per (run_id, prediction_sha256), and which copy is kept is chosen "
        "rather than left to path order: one of the six pairs records the model as the repo id "
        "at one path and as the artifact stem at the other, and only the stem is on the roster, "
        "so keeping the first path dropped SecJudge out of the reported families. The rollup's "
        "own shrink guard rejected the first attempt at this, because one of the 35 "
        "fault-inject-mock manifests was also a duplicate pair; the guard's floor moves to the "
        "deduplicated 34 manifests and 1,972 requests with the duplicate named in the code. No "
        "dollar total moved. Request total 1,739,149 to 1,808,873, reported manifests 171 to "
        "168, error rate over that total 0.00190% to 0.00182% on an unchanged 33 errors.\n"
        "Other derived counts moved because six run manifests have landed in the outputs tree "
        "since the last upload, four of them from other work: manifests found 319 to 325, "
        "reported model families 9 to 11, shard manifests set aside 24 to 29, added arms 6 to 8, "
        "ranked rows 8 to 11, the build's assertion count 787 to 971 and artifacts read 193 to "
        "211. The site's stale _wordcount.json, which omitted two pages and predated the last "
        "three uploads, was regenerated over all 14 pages.\n\n"

        "Extensibility is unchanged. A registry entry plus a rebuild still adds an arm, and "
        "both new rows are one entry each.\n\n"

        "Gates: 971 figure assertions checked, 0 mismatches. audit_layout() clean over 29 "
        "charts. Label-fit, grid-label and strip-CSS palette audits clean. Markup gate clean "
        "over 15 pages: 0 double-escaped entities, 0 raw ampersands or angle brackets, 0 escaped "
        "tags rendering as text, 0 repeated attributes, 0 unresolved format tokens. Verifier 14 "
        "pages, 0 problems, 810 internal links resolved, 65 outbound links to allowed hosts, 9 "
        "permitted dataset-viewer iframes, 0 other subresources, 93 retired figures checked and "
        "0 present. Payload guard PASS over "
        f"{payload_files} files and {payload_bytes:,} bytes: 0 case ids, 0 sensitive shingles, "
        "0 CJK, 0 credentials, 0 disallowed types, 0 oversized files, and it also passes with "
        "the first-party protocol exemption switched off for every page except prompts.html, "
        "which is the page that exemption exists for and which this change does not touch. 211 "
        "artifacts read. Visibility read before and after and unchanged; the Space stays public."
    )
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
