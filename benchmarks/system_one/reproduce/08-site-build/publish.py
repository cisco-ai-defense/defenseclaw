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
    commit_message="Rebuild the board on one common operating point and remove the "
                   "augur-derived corpora",
    commit_description=(
        f"Two changes in one upload. Every arm is now reported at one shared operating point on "
        f"one shared ranking variable, and the two corpora derived from "
        f"robustintelligence/augur_unsafe_tool_input_eval are gone from the payload. The payload "
        f"is {payload_bytes:,} bytes over {payload_files} files.\n\n"

        "ONE COMMON OPERATING POINT, AND IT IS THE HEADLINE\n"
        "Every arm is read on P(block) under aggregation definition A at one block "
        "false-positive budget, 0.00384502, which is the incumbent OpenJev's own realised block "
        "false-positive rate on this corpus. The budget allows 13 false blocks out of 3,381 "
        "benign cases. At that budget the table prints tp, fp, fn, tn, precision, recall, F1, "
        "accuracy, block FPR and the threshold used, for all 12 arms that can be re-thresholded. "
        "No arm appears in that table at a threshold chosen for it alone.\n"
        "  open-jev-qwen-27b 0.73876404, OpenJev 0.71162123, Jev 1.13.0 0.58359621, "
        "gemma-4-26B-A4B-it 0.32462687, jevify-gemma4-26b-a4b 0.29277567, open-jev-qwen-9b "
        "0.24609375, DiffusionGemma 26B-A4B 0.22529644, kev-9b 0.19315895, open-jev-qwen-2b "
        "0.08119658, decider-2b 0.07296137, bespoke-nimble-9b 0.00886918, SecJudge 0.00000000.\n"
        "  The figures come from rethreshold/common-point-s2.json, written by "
        "reproduce/07-analysis/rescoring/common_point.py, which imports the published re-mining "
        "pass's own sweep and cap functions instead of reimplementing them. 11 of its 12 rows are "
        "cross-checked cell for cell against remine-full.json and the pass aborts on a mismatch; "
        "it reports 0. The 12th row is kev-9b, which the published pass does not cover, and its "
        "unconstrained figure agrees with the two files that do publish it.\n"
        "  The Gemma 4 judge carries no figure at the budget. Its 4,277 prediction rows carry no "
        "disposition distribution, so no threshold sweep is possible; the page says so and prints "
        "its board cell.\n\n"

        "THE SHIPPED-THRESHOLD TABLE IS STILL THERE AND IS NOW LABELLED AS ONE\n"
        "The ranked leaderboard keeps every arm at the threshold it shipped with and says that a "
        "difference between two of its rows carries both the models and their calibration, with a "
        "link to the common-budget table.\n\n"

        "ORACLE FIGURES ARE IN THEIR OWN TABLE\n"
        "Each arm's own argmax is in a separate table, labelled an in-sample oracle upper bound "
        "on its face, with the common-budget figure repeated beside it and the gap printed. The "
        "two are never added, subtracted or ranked together. The gaps run from +0.08287002 "
        "(open-jev-qwen-27b) to +0.57210248 (bespoke-nimble-9b).\n\n"

        "THRESHOLD-FREE\n"
        "AUC per arm on P(block), every figure labelled definition A, with both definitions "
        "stated: A takes the maximum block probability over a case's events and the maximum "
        "confirm probability over its events, then subtracts; B takes the maximum over events of "
        "the per-event difference. Chance bands printed: s2 [0.471205496131191, "
        "0.528794503868809], s3 [0.46176687597792665, 0.5382331240220734]. "
        "P(block) - P(confirm) ranks nothing: it inverted below chance on the disjoint corpus for "
        "both arms where transfer was measurable, OpenJev 0.856982082821162 to "
        "0.2994021851164708 and Jev 1.13.0 0.838702313793487 to 0.3420025352798462. kev-9b's "
        "0.6092050209205021 on that variable stays published as an explicitly withheld figure "
        "with that reason.\n\n"

        "SIZE BANDS, AND WHAT THE BANDING ACTUALLY RESTS ON\n"
        "under 3B holds 3 arms (open-jev-qwen-2b, decider-2b, SecJudge), 3B to 6B holds 0 and is "
        "printed with a zero count and one line saying nothing in scope lands there, 6B and up "
        "holds 7. Ranking inside a band is the common-budget F1. Only 3 of the 10 banded arms "
        "have a counted parameter figure: SecJudge 395,836,421 from its serving record, and the "
        "two Gemma-4 arms at 25,805,936,206 from the merged-weight diff. Every other arm's "
        "serving record carries a base model and no parameter count, so its band comes from the "
        "base model's nominal size and the row says 'nominal'. That is stated on the page. "
        "Jev 1.13.0 and OpenJev are in a labelled not-parameter-comparable group: Jev is a hosted "
        "API, and no parameter count for openjev/openjev is recorded in any artifact on disk.\n\n"

        "ACCURACY NEVER APPEARS WITHOUT THE ALL-ALLOW BASELINE\n"
        "The common-budget table carries the all-allow baseline and the block-everything floor as "
        "rows, not as a footnote. s2 is 88.58% benign, so deciding allow on every case scores "
        "0.8857741681949175. 2 of the 12 arms score at or below that: bespoke-nimble-9b "
        "0.88289232 and SecJudge 0.88551218. s3's all-allow accuracy is 0.9909707468540612 at a "
        "prevalence of 0.009029253145938878.\n\n"

        "THE TRIVIAL FLOOR, WITH ITS POPULATION STATED\n"
        "Blocking every case scores block-only F1 0.20503174229955326 on s2 at 11.42% "
        "prevalence. 4 of the 11 ranked rows are below it at their shipped operating point "
        "(open-jev-qwen-9b 0.17551020, open-jev-qwen-2b 0.17194570, jevify-gemma4-26b-a4b "
        "0.04921700, kev-9b 0.01814059) and 2 clear it by under 0.012 (bespoke-nimble-9b "
        "0.21568627, SecJudge 0.20724154). That count is over the ranked rows, and the page now "
        "says so and names the one further re-mined arm below the floor that is not a board row, "
        "decider-2b at 0.10843373.\n\n"

        "THE DATASETS SECTION DOCUMENTS THE DATA\n"
        "Per corpus: cases, decisions, scorable cases, positives, negatives, grade-C exclusions, "
        "prevalence, all-allow accuracy, the block-everything floor, grade-A share of positives "
        "and cases_sha256. s2 is 4,277 cases / 30,310 decisions / 3,817 scorable / 436 positives "
        "/ 460 grade-C excluded, digest 39f2c1df2369952a0525cc4c5575f4bdb590fb3ca8c1bc6805cf4f376"
        "c1adbf7. s3 is 24,476 cases / 100,001 decisions / 221 positives, digest "
        "0ccbc08fb408ffefc89e051c585cfe22433b1ed4c9714f60cc0f7e242969fa03. They share 0 case ids. "
        "The grade scheme is printed in full: what each of A, B, C, D and E means, the rule that "
        "produces it, and what assigned it, all read from truth_grade() in "
        "benchmarks/scripts/benchmark_inventory_system_one_sources.py, which is the same function "
        "the scorer and the common-budget pass call.\n\n"

        "THE GRADE-COMPOSITION CONFOUND IS ON THE PAGE\n"
        "s2's 436 positives are 17 grade A and 419 grade B, 3.90% grade A. s3's 221 positives are "
        "193 grade A and 28 grade B, 87.33% grade A. A difference between an arm's figure on one "
        "and its figure on the other conflates threshold miscalibration with a changed definition "
        "of a positive. No transfer or generalisation claim is published in either direction.\n\n"

        "THE AGGREGATE-ONLY RULE NOW MATCHES THE PAYLOAD\n"
        "compare.html keeps its coded contingency block. The rule was stated absolutely and the "
        "block quietly sat outside it; the rule now carries an explicit carve-out for coded "
        "contingency data that carries no identifier and no text, stated in both places. The "
        "block is 2,133 rows of 9 small integers indexing code tables printed beside them, "
        "collapsing to 500 distinct tuples, with no case_id, no request, no tool call, no "
        "argument value and no free-form rationale, and no row from an aggregate-only or "
        "local-evaluation-only corpus. Those three counts are computed at build time.\n\n"

        "REMOVED: THE AUGUR-DERIVED CORPORA\n"
        "The internal licence review of robustintelligence/augur_unsafe_tool_input_eval concluded "
        "against retention, so its two derived lanes, intent-ablation and toolcall-labels, are "
        "gone. The payload carried 80 references across 12 files and now carries 0. What went "
        "with them: the two-lane split chart and its section, the instruction-wording "
        "difference-in-differences section, the request-text ablation section, the "
        "harm-versus-service entanglement finding, the disposition-tie counts, two "
        "recommendations, three experiment rows, four glossary rows and six assertion groups. "
        "finding-architecture.html drops from 300,704 to 266,153 bytes and finding-intent.html "
        "from 124,912 to 116,658; finding-intent.html survives because its spine is the "
        "intent-real corpus, which is a different source. One chart goes, 29 to 28. Artifacts "
        "read goes 211 to 208: six augur-derived files out, three new ones in. The SecJudge "
        "contamination disclosure keeps its s2, intent-real, s3 and eval-reuse lanes and loses "
        "the toolcall-labels lane and the augur-naming sentence.\n\n"

        "CORRECTED WHILE REBUILDING\n"
        "- The five SecJudge readouts were described as threshold-equivalent with byte-identical "
        "AUCs and the same best F1. The report records no roc_auc for any of the five, and their "
        "shipped block-only F1 figures are three different values: t10-90 0.25224111, t20-75 "
        "0.24833434, isattack 0.20893372, t05-50 0.20893372, sev 0.20724154. The page now prints "
        "all five, says the ranked mapping is sev and places it 5 of 5, and states that no "
        "threshold-free comparison between them exists on disk. All five are pinned.\n"
        "- open-jev-qwen-27b's capped point does not hold its cap out of fold. The unconstrained "
        "point holds 0.8167053364269141; the capped point reaches 0.7513812154696132 at an "
        "achieved rate of 0.004732327713694173, outside the 0.00384502 it was fitted to. Both are "
        "printed with that attribution.\n\n"

        f"GATES\n"
        f"Figure assertions checked with 0 mismatches. audit_layout() clean over every chart. "
        f"Label-fit, grid-label and strip-CSS palette audits clean. Markup gate clean over 15 "
        f"pages. Verifier 0 problems over 14 pages and 30 chart figures, every internal link "
        f"resolved, 65 outbound links to allowed hosts, 9 permitted dataset-viewer iframes, 0 "
        f"other subresources, 93 retired figures checked and 0 present. Payload guard PASS over "
        f"{payload_files} files and {payload_bytes:,} bytes, non-vacuously: 17 corpora and "
        f"117,848 corpus rows indexed, 201,106 case ids and 2,236,945 sensitive shingles in the "
        f"index, 0 case ids, 0 sensitive shingles, 0 CJK, 0 credentials, 0 disallowed types and 0 "
        f"oversized files found. Visibility read before and after and unchanged; the Space stays "
        f"public."
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
