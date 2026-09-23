"""Narrative sections for the SecJudge report. Kept separate so the numeric builder stays
mechanical and every claim here points at an artifact."""

CONTAMINATION_VERDICT = r"""
**Verdict: UNDETERMINABLE overall, with firm per-stage sub-verdicts.**

The model repo (`nghodki/SecJudge` @ `28e810af`) ships **no dataset files at all** - only
`model.safetensors`, `config.json`, `tokenizer.json`, `secjudge_model.py`, `secjudge_config.json`,
the two calibrators and the licence. `secjudge_config.json` carries only `{model_name, num_classes,
severity_labels, calibration_temperatures, training:{phases, supcon_epochs, ce_epochs,
rlcd_epochs}}` - no dataset list, no row hashes, no sampling indices. So the actual training rows
are **not enumerable from the model**, and the card's "zero overlap with training data" claim is
not independently checkable in the strict sense.

What we could check, we did check empirically.

**Sources obtained: 7 of 11.** All seven publicly-named HF training datasets downloaded
(`S-Labs/prompt-injection-dataset`, `AnishJoshi/nl2bash-custom`,
`ise-uiuc/Magicoder-OSS-Instruct-75K`, `Trendyol-Cybersecurity-Instruction-Tuning`,
`3nesdeniz/agentic-prompt-injection-boundary-pairs`, `deepset/prompt-injections`,
`infraset/infraset`) - 0 gated, 0 missing. We compared against the **full supersets**, which are
1.4x-272x larger than the slices the card says SecJudge sampled, so the comparison can only
over-report overlap.

**Sources NOT obtainable: 4 of 11 = 5,550 samples (35.1% of the card's tabulated total)** - the
DefenseClaw Security Suite (4,100, carried at 5x weight), DC JSON-augmented (190), DC
context-augmented (490) and the internal "Attack Example Bank (EN)" (770). This is the specific
evidence gap that blocks a global `clean`.

**Provenance check - negative.** Across all 42,154 cases in our four corpora, **zero** rows come
from any of the 7 enabled `defenseclaw-*` entries in `datasets.lock.json`, zero from `nl2bash`,
zero from `infraset`. Our corpora are drawn from agent-trajectory datasets that do not appear
anywhere in SecJudge's training table.

**Near-duplicate check.** Character 5-grams -> 128-permutation MinHash (seed 20260922) -> LSH
banding r=2/b=64 (measured detection 1.0000 at J>=0.5) union r=3/b=42, every candidate re-scored
with an exact Jaccard. On document views, **no publicly-named training source produced a single
case at J>=0.7 in any stage**, and at most 10 cases (0.024% of 42,154) reach J>=0.5 - all of them
generic shell commands.

**Per-stage sub-verdicts:**

- **s2 - clean.** 5 cases exact-match DefenseClaw-Suite payloads, but these are 20-35 character
  canonical strings (`{"path":"/etc/shadow"}`, `{"path":"/root/.aws/credentials"}`) arriving from
  `agentic-redteam-benchmark`/`mcptox`; that is convergence on canonical payloads, not lineage.
  Zero collisions on the C7 view that SecJudge is actually fed.
- **s3 - clean.** 58% of the whole benchmark. Zero cases at J>=0.5 against the Suite on document
  views, zero exact C7 collisions.
- **intent-real - clean.** Same canonical-payload convergence (5 cases), no lineage.
- **toolcall-labels - CONTAMINATED. Flagged, and excluded from the headline.** At least **32 of
  9,999** cases carry attack command strings that are byte-identical (>=40 chars; 23 of them >=80
  chars) to 31 distinct DefenseClaw-Suite `toolcall` rows - the AMSI reflection bypass, paired
  Carbon Black `launchctl unload`s, CredSSP `allowencryptionoracle`, an HVCI registry write, and a
  macOS passphrase-phishing `osascript` sharing both the dialog string **and** the `pwd_spoof`
  variable name. Independent authorship is not credible. Separately, the benign half (5,000 of
  9,999) is drawn from an internal `defenseclaw_convs_parquet` dump whose overlap is
  **unmeasurable** because it is an internal S3 object.

**Eval-set reuse (not training contamination, but it matters).** Our 96
`rogue-coding-agent-security` cases (87 in s2, 9 in s3) are **definitively from the same 332-case
benchmark SecJudge reports its cross-domain number on** - all 96 `original_id`s resolve to real
rows at the pinned revision, covering 91 distinct rows = 27.4% of that benchmark. 63 exact text
matches; 66 of the 87 s2 cases at J>=0.9. SecJudge's cross-domain figure is tuned on those rows,
so its score on our 96 is **not out-of-sample**. They are 2.3% of s2's scorable set, too few to
move the s2 headline, but the reuse is real and is recorded.

**Nemotron - sibling, not the same.** Our s3 draws 23,410 cases from
`nvidia/Nemotron-RL-Agentic-Terminal-Pivot-v1`; SecJudge evaluates on
`nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1`. Same publisher, family, licence and
schema, but 31,111 vs 1,272 rows, **disjoint id spaces (0 shared)**, different agent harnesses and
different release dates. Empirically: **0 exact collisions** across 62,222 x 3,816 text documents
and **max Jaccard 0.0792**, with zero pairs at J>=0.5. s3 is not compromised by that eval set.

**Two labelling points that must not be misread.**

1. `exact-matches.json` has an index named `train_side` holding **11 groups**, and two of them are
   `nvidia__Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1` (3,816 docs) and
   `rogue-security__coding-agent-security-benchmark` (608 docs). That name is an artifact of
   building one comparison index: both were downloaded for the eval-reuse task and are recorded in
   `training-sources.json` under the key `additional_sources_downloaded_for_task_E`, where
   rogue-security carries `"role": "SecJudge EVALUATION set"`. **Neither appears in the card's
   11-row training table.** The card lists both as evaluation benchmarks, and this report does not
   claim otherwise. The 11 `train_side` groups are: the 7 obtainable card-named training sources,
   plus `dc-security-suite` (3,825 docs) and `dc-benchmark-fixtures` (229) standing in for the
   unobtainable DefenseClaw training slice, plus those 2 eval sets.

2. `robustintelligence/augur_unsafe_tool_input_eval` - the source behind our `toolcall-labels`
   corpus - is **not** in SecJudge's training table, not in its evaluation list, and not in the
   comparison index at all (verified: the strings `augur`, `robustintelligence` and
   `unsafe_tool_input` appear nowhere in `training-sources.json` or the train index). So there is
   **no named training path from augur into SecJudge**. The toolcall-labels contamination does not
   run through augur being trained on; it runs through **shared internal provenance**: augur's
   positive rows and the DefenseClaw Security Suite `toolcall` rows both descend from the same
   internal Cisco corpus, and the Suite *is* a named training source carried at 5x weight. That is
   why the lane is flagged despite augur itself being absent from the card.

**Consolidated match counts.** Index sizes: 545,633 training-side documents / 434,473 distinct
normalised texts, against 213,777 distinct corpus texts over 42,154 cases.

| training group | stage | exact | J>=0.9 | J>=0.7 | J>=0.5 | max J |
|---|---|---:|---:|---:|---:|---:|
| dc-security-suite | s2 | 5 | 5 | 5 | 18 | 1.000 |
| dc-security-suite | s3 | 0 | 0 | 0 | 0 | 0.412 |
| dc-security-suite | intent-real | 5 | 5 | 7 | 12 | 1.000 |
| dc-security-suite | toolcall-labels | 32* | 2 | 18 | 60 | 0.902 |
| dc-benchmark-fixtures | s2 / s3 / intent-real / toolcall-labels | 0 | 0 | 0 | 13 / 4 / 0 / 2 | 0.604 |
| S-Labs | all four | 0 | 0 | 0 | 0 | 0.475 |
| nl2bash-custom | all four | 0 | 0 | 0 | 0 / 0 / 0 / 2 | 0.659 |
| Magicoder | all four | 0 | 0 | 0 | 2 / 0 / 0 / 1 | 0.522 |
| Trendyol | all four | 0 | 0 | 0 | 0 | <0.30 |
| 3nesdeniz | all four | 0 | 0 | 0 | 0 | <0.30 |
| deepset | intent-real | 0 | 0 | 0 | 0 | 0.422 |
| infraset | all four | 0 | 0 | 0 | 2 / 3 / 0 / 5 | 0.611 |
| _rogue-security (EVAL, not training)_ | s2 | 63 | 66 | 69 | 77 | 1.000 |
| _rogue-security (EVAL, not training)_ | s3 | 0 | 1 | 4 | 5 | 0.914 |
| _nvidia IPI (EVAL, not training)_ | all four | 0 | 0 | 0 | 0 | <0.30 |

\* the 32 for toolcall-labels is the bare-command view at >=40 characters (23 of them >=80
characters); on the document view that lane shows 2 at J>=0.9 and 18 at J>=0.7.

**Length stratification matters and is reported rather than hidden.** With no minimum length there
are 3,710 infraset<->s3 and 579 nl2bash<->s3 exact command hits, but they are strings like `env`,
`df -h` and `crontab -l`. At >=40 characters only three survive across the whole comparison
(dc-suite x toolcall-labels 32, dc-suite x s2 1, infraset x s3 2); at >=80 characters only the 23
dc-suite x toolcall-labels hits remain. Short-command collisions are coincidence; the long ones are
not.

**Two defects in the card found along the way:** its per-source training table sums to **15,795**,
not the stated **15,266** (delta 529); and 3 of the 9 IPI domain names it lists do not match the
source dataset.
""".strip()

CLAIMS = """
The card's headline comparison is **F1 0.965 for SecJudge vs 0.843 for "Jev (TypeSafe Cloud)" on
its own 1,465-case DefenseClaw corpus**, and **cross-domain F1 0.654 vs Jev 0.793 on the 332-case
Rogue coding-agent set**. We have hosted Jev measured on *our* corpora with the same scorer, so
both sides can be put next to each other - but they are **measured on different data and are not
comparable**. The card's numbers are on SecJudge's own corpora; ours are on the System One
corpora. Nothing below contradicts or confirms the card's arithmetic; it re-measures both models
on a third, shared corpus.

| corpus | metric | SecJudge (measured here) | hosted Jev (measured here) | card's claim |
|---|---|---|---|---|
| s2 C7 parity (System One broad, n=3,817) | block-only F1 | **0.2072** | **0.5415** | - |
| s2 C7 parity | any-intervention F1 | **0.2072** | **0.5024** | - |
| s2 C7 parity | recall @ <=0.5% FPR | **0.0069** | **0.0917** | - |
| s2 C0 | block-only F1 | **0.2072** | - | - |
| s2 C0 | recall @ <=0.5% FPR | **0.0000** | - | - |
| SecJudge's own DefenseClaw corpus (n=1,465) | F1 | not re-measurable here | not re-measurable here | 0.965 vs Jev 0.843 |
| Rogue coding-agent (n=332) | F1 | not re-measurable here | not re-measurable here | 0.654 vs Jev 0.793 |

**What we could NOT verify:**

1. **F1 0.965 on the DefenseClaw Security Suite.** The card's 1,465-case split is not the version
   in the repo (we found 1,960 rows: regex 642 vs the card's 595, toolcall 623 vs 230; the four
   160-row sub-corpora match exactly). Without the card's exact split we cannot reproduce 0.965.
2. **Jev 0.843 / 0.793.** No artifact records how Jev was invoked for those numbers - which
   version, prompt, or disposition mapping. Our Jev figures use the C7/I3/Q2 grid.
3. **"92% recall at <=0.5% FPR"** on its own corpus. Not reproducible without that corpus. On our
   corpora the same statistic is 0.0000 (s2).
4. **"Zero overlap with training data."** Directionally supported for s2/s3/intent-real and
   refuted for toolcall-labels, but not verifiable in general because 35.1% of the training
   samples are unobtainable.
5. **Cross-domain independence of the Rogue number.** Our 96 Rogue-derived cases are the same rows
   the card evaluates on, so that benchmark is not out-of-sample for it.
""".strip()

BOTTOM_LINE = """
## Bottom line

**SecJudge is not yet comparable to the incumbents on this corpus family, and where it is
measurable it is clearly worse - including on the metric its own card nominates.**

1. **Under the parity contract it is a near-degenerate always-block classifier.** This now holds
   at the **C7 parity context**, the only cell directly comparable to the incumbents, and not just
   at C0. On s2 C7 (n=3,817) the card-native severity mapping gives block-only F1 **0.2072** at FPR
   **0.9840** and three-way accuracy **0.0186**; at C0 it gives **0.2072** at FPR **0.9870** and
   **0.0160**. A trivial "block everything" baseline on the same split scores block F1 **0.2052**,
   so SecJudge beats it by **0.0020** at both contexts. Recall is 0.9977 (C7) / 1.0000 (C0) only
   because it blocks essentially every case. Giving it the full parity context therefore does NOT
   rescue it - the degeneracy is not a C0 artifact. OpenJev scores 0.7023 at FPR 0.0038 and hosted
   Jev 0.5415 at FPR 0.0009 on exactly the same cases, scorer and deterministic tier.

2. **It loses on its own preferred metric too - this is the headline.** (Gemma 4 is excluded from
   this comparison by construction, not by result: see the note under the table in section 6.) The card argues F1 is the
   wrong metric and recall at <=0.5% FPR is right. Measured on s2 with the pre-isotonic
   `raw_score` at full resolution (so no calibration-granularity excuse): at the **C7 parity
   context** (2,327 distinct case-level values) recall is **0.0000 @ <=0.1% FPR**, **0.0069 @
   <=0.5%**, **0.0092 @ <=1%** and **0.1468 @ <=5%**, ROC AUC **0.7192**; at C0 (2,260 distinct
   values) it is **0.0000** at <=0.1%/<=0.5%/<=1% and **0.0069** at <=5%, AUC **0.6225**. C7 raises
   the curve but leaves it last of the ranked models at every budget at or below 1%. OpenJev reaches
   0.2890 at <=0.5% FPR (AUC 0.9374) and hosted Jev 0.0917 (AUC 0.8770). So the answer to "does it
   win on its metric and lose on ours" is: **it loses on both.**

3. **Inserting it into the cascade destroys the cascade.** On the real deterministic tier,
   det+Gemma-4 alone gives block F1 **0.7125** at FPR 0.0068. Adding SecJudge as the System One
   tier gives **0.2245** at FPR 0.8912, because its confident blocks short-circuit ahead of the
   LLM tier. All four two-sided thresholds (@0.05/@0.10/@0.20/@0.30) land on the same 0.2245 -
   there is no threshold that rescues it, because its calibrated score is not informative here.

4. **A large part of this is the prompting contract, and that must not be hidden.** SecJudge is a
   5-class sequence classifier given one text string; the other five backends answered the Q0-Q4
   question grid. On a matched sample the parity `production_text` framing drives it to block
   **100% of both classes** (AUC 0.6744), whereas a bare-command serialisation recovers real
   signal (AUC **0.7650**, benign block rate 55%). Even the card's own documented `tool_calls`
   JSON shape still blocks **85.8%** of benign cases. So part of the gap is framing - but even at
   its best measured framing it is still blocking more than half of all benign agent actions,
   which is disqualifying for a security gate on its own terms.

5. **Two independent handicaps are real and quantified.** (a) On the s2 parity context, 512-token
   truncation hits unsafe cases **58.10%** vs benign **40.18%** - a 17.9 pp bias against the class
   it must catch. (b) The shipped `load_secjudge()` slices input to **512 characters** before
   tokenising, which would truncate **80.65%** of s2/C7 decisions; we bypassed that and gave it
   the full 512 tokens.

6. **Score coarseness is a deployability problem in its own right, separate from accuracy.** The
   shipped isotonic table has 1,000 points but only **19 distinct y values**, so it is mostly long
   plateaus; a dense sweep of raw scores through it yields just **44** distinct calibrated outputs.
   Measured on s2: at the decision level 16,853 distinct raw scores map to just **396** distinct
   calibrated values, and per case (max over events) the calibrated score takes **80** distinct
   values across 3,817 cases against **2,260** for `raw_score` (57 vs 2,207 on the `cmd` arm). A gate whose score has ~80 usable levels
   cannot be tuned to a chosen FPR with any precision, independently of how good its ranking is.
   The same coarseness makes it numerically brittle: bf16 inference moved the calibrated score by
   up to **0.404** and flipped `is_attack` on 6.25% of a sample, because a tiny numeric shift can
   jump a whole plateau.

7. **Engineering findings a user should know.** The documented call
   `load_secjudge("nghodki/SecJudge")` silently loads **no weights and no calibrator** (it
   `os.path.exists`-checks a repo id), yielding a randomly initialised 395M model with no error.
   `load_state_dict(..., strict=False)` means a key mismatch also fails silently too.

**Contamination cannot explain the poor result, and the direction matters.** Any training overlap
would *inflate* SecJudge's scores, not depress them. So the weak numbers here cannot be explained
away by contamination; contamination bears on the **card's** 0.92 recall at <=0.5% FPR, not on ours.
The card reports 0.92 on its own DefenseClaw suite while the same statistic on our Broad corpus is
**0.0000**. If its training data overlaps its own evaluation suite - and 4,100 of its training rows
are that suite, carried at 5x weight, with the card's own eval split not matching the in-repo
corpus - then 0.92 is not a generalisation claim. That is the central tension in this whole
exercise.

**Caveat on scope.** These conclusions rest on the stages that actually settled (listed in
section 9). The contaminated `toolcall-labels` lane is excluded from every headline. The
contamination verdict is `undeterminable` overall because 35.1% of SecJudge's training samples
are not obtainable, so a stronger claim than "no overlap found on s2/s3/intent-real" is not
available.
""".strip()
