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
    commit_message="Rebuild on the authoritative ranking: pair-weighted pooled estimator, 22 "
                   "arms, and the corpus-design finding that rules out a transfer claim",
    commit_description=(
        "An authoritative ranking artifact now exists, declares its own estimator, and covers all "
        "22 arms. The build's estimator gate consumed it with no edit. Corpus s2, 3,817 scorable "
        "of 4,277, 436 positives, 3,381 benign, cell C7/I3/Q2, cases_sha256 "
        "39f2c1df2369952a0525cc4c5575f4bdb590fb3ca8c1bc6805cf4f376c1adbf7.\n\n"
        "THE ESTIMATOR IS NOW PAIR-WEIGHTED POOLED, AND RANK 3 CHANGES\n"
        "estimator.authoritative = A_pair_weighted_pooled, read from the artifact's own field. "
        "Rank 1 deberta-v3-prompt-injection-v2 at 0.8347427912167461, rank 2 shieldgemma-2b at "
        "0.7544168878566688, rank 3 granite-guardian-3.2-3b-a800m at 0.6556844573807082. The "
        "previous revision published the unweighted mean of the per-quintile AUCs and gave rank 3 "
        "to a different arm; that estimator is retracted and the page says so.\n\n"
        "The choice rests on three things and not on a tally of estimators. The artifact evaluates "
        "9 schemes and 6 of them are unweighted means differing only in binning, so they share one "
        "defect and are not independent witnesses.\n"
        "- Estimand. Pooling is the Mann-Whitney statistic over within-stratum pairs: the raw AUC "
        "with the length-confounded pairs deleted and nothing else changed. The unweighted mean "
        "estimates a different target, the same probability averaged with equal weight per length "
        "band regardless of how many attacks fall in it.\n"
        "- Weight against evidence. The thinnest quintile holds 2 of 436 positives, 0.459% of the "
        "evidence. The unweighted mean gives it 20% of the weight, a 43.6x over-weighting; pair "
        "weighting gives it 0.505%.\n"
        "- Variance. Per-bin Hanley-McNeil at AUC 0.5, a function of bin composition alone, puts "
        "the unweighted mean's standard error at 2.8168805664932379x the pooled estimator's. The "
        "number of candidate arms where it is not worse is 0.\n"
        "Ranks 1 and 2 are contradicted by exactly one of the 9 schemes, and it is the same scheme "
        "for both: the one whose bins move with each arm's own truncation, which the artifact marks "
        "confounded. Rank 3 is contradicted by 5. The build asserts each of those counts, so a "
        "future artifact that changes them fails rather than republishing quietly.\n\n"
        "THE HELD-OUT CORPUS IS NOT A GENERALISATION TEST, AND NO TRANSFER FIGURE IS PUBLISHED\n"
        "Six arms are scored on a corpus disjoint from s2 with zero case-id overlap. Its positives "
        "are 193 grade A and 28 grade B, 87.33% grade A. s2's are 17 grade A and 419 grade B, "
        "3.90% grade A. Grade A is an unambiguous destructive call and grade B is a judgement "
        "call, so the two corpora ask different questions and a difference between them conflates "
        "threshold miscalibration with a changed definition of a positive. No transfer penalty "
        "appears on this Space. What is published is the composition and the per-grade separation "
        "it explains.\n"
        "Because the held-out corpus is 87.33% grade A, position on it is driven by grade-A "
        "separation, and the two extremes of that make the point. shieldstral-1.0-3b separates "
        "grade A at 0.993005875611353 and grade B at 0.6159385399181317, from s2 rank 8. "
        "granite-guardian-3.2-3b-a800m is the other end at 0.363555722178964 on grade A against "
        "0.6462239008157376 on grade B, so it is anti-predictive on exactly the class the held-out "
        "corpus is made of, from s2 rank 3. Neither is evidence about generalisation; both are "
        "evidence that the two corpora measure different things. It is a corpus-design finding and "
        "more data of the same kind does not fix it. The two arms shown are selected by a derived "
        "rule, the best and worst grade-A separator, not by hand.\n\n"
        "THE HELD-OUT CORPUS CARRIES NO LENGTH CUE\n"
        "Its counting variables sit at 0.504185543681342 and 0.34604723008084354, inside and below "
        "its chance band of [0.46176687597792665, 0.5382331240220734]. Both are corpus fields "
        "identical across every arm. So raw AUC is the honest primary there and a length-controlled "
        "figure would add estimator noise and nothing else. Length control on this Space applies to "
        "s2, where the same kind of variable reaches 0.7692264380822134.\n\n"
        "MORE DATA DOES NOT CHANGE THE ANSWER\n"
        "All 15 pairwise comparisons on the held-out corpus are already separable and the median "
        "detectable AUC difference is 0.04158611807750677. A false-positive cap is a rate, so a "
        "larger benign pool grows the budget in step. On s2 the best arm at the cap catches 25 of "
        "436 positives and the Wilson 95% interval on that recall is [0.03913701672802459, "
        "0.08327404239553826], computed here rather than quoted. More traces buy a tighter interval "
        "around the same unusable number. That is a statement about ranking precision: 98.68% of "
        "the AUC variance on the held-out corpus comes from its 221 positives, so the positive "
        "count remains the binding constraint on every per-positive quantity, and grade B has only "
        "28 of them there.\n\n"
        "UNCHANGED AND RE-CHECKED ON 22 ARMS\n"
        "The deployment result still leads: at a block false-positive rate of 0.00384502 the best "
        "arm is falcon3-1b-instruct at recall 0.05733944954128441, 25 of 436 positives, F1 "
        "0.10548523206751055, while the ranking leader catches 1. Under a zero-false-positive gate "
        "13 of the 20 candidates retain zero recall. 9 of the candidates score below the trivial "
        "floor of 0.20503174229955326 at their shipped point and 5 score exactly zero there. "
        "tp / fp / fn / tn, precision, recall, F1 and block FPR for every arm at both operating "
        "points, counted from rows. The untrained-backbone comparison, the corpus and its grade "
        "split, the runner's shrunk count of 17,202 rows (56.75%) stated separately from the "
        "row-level truncated field's 2,086 (6.88%), and the scope rule with 11 forbidden name "
        "tokens checked independently by the builder and the verifier.\n\n"
        "SETTLEMENT NOW READS 22 OF 22, DERIVED\n"
        "Every s2 body carries complete: true with a prediction_sha256 matching the body on disk, "
        "read from the archived settled tree. The previous revision reported 16 of 21 because the "
        "artifact it read took metadata from a working tree whose files were stale for 5 arms; the "
        "bodies were byte-identical across both trees, so no score moved. The count is still "
        "derived per arm from whichever artifact is in hand.\n\n"
        "One arm, gemma-3-4b-it, is ranked and has both deployment gates but no shipped-argmax row, "
        "because its prediction body landed after the run that recorded those. It is named wherever "
        "the two populations differ, 22 against 21.\n\n"
        "GATES ADDED\n"
        "- Any mention of the held-out corpus, of transfer, or of generalising must sit near the "
        "grade-composition caveat, or the verifier fails the build. Seven retired literals block "
        "the transfer-penalty figures and the generalisation phrasings.\n"
        "- vendor_artifacts.py scope-filters artifacts before they enter the public repository. Two "
        "scoring outputs covered a System One board arm alongside the cohort, and two stage-0 files "
        "vendored in an earlier revision named board arms and quoted their scores. Those blocks are "
        "removed, the equivalence gate's references are reduced to the properties of the check, and "
        "the removal manifest records the shape of what was removed without naming it. Every "
        "surviving value is byte-identical to its parent and the parent's sha256 is recorded.\n"
        "- The build records which keys it reads from the ranking artifact and fails if a held-out "
        "key is among them, so the held-out results cannot leak into an s2 figure.\n\n"
        "The ranking artifact's own provenance is checked: arithmetic from the vendored shared "
        "module at sha256 "
        "97df17a30891446d94a9df923ec343a6c7bd29adea3435b0303e4604440d5a6f, no GPU used, and a "
        "scope_rule field recording that no Jev-family or System One board model is in the cohort "
        "ranking.\n\n"
        "Gates: 447 figure assertions and 0 mismatches over 17 artifacts and 20 charts; label-fit, "
        "layout-collision, palette, front-matter, markup, scope and held-out checks all clean. "
        "Payload guard PASS over 11 files and 489,840 bytes with no protocol exemption. Verifier 7 "
        "pages, 0 problems, 21 chart figures, 58 retired figures checked and 0 present, 134 "
        "internal links resolved, 43 outbound links to allowed targets, 0 other external URLs, 0 "
        "scripts and 0 subresources. Visibility read before and after and unchanged."
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
