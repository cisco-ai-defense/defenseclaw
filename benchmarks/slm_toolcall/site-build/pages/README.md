---
title: SLM tool-call security
emoji: 🔧
colorFrom: gray
colorTo: green
sdk: static
app_file: index.html
pinned: false
license: other
short_description: Small local models on destructive tool-call classification
---

# SLM tool-call security

{{fig:roster.n}} small and local models scored on one question: given an agent's trajectory so
far and the tool call it is about to make, does that call have to be blocked.

## Scope

This Space carries small and local models measured on destructive tool-call classification.
Cascade guardrail models on the DefenseClaw parity grid, and the Jev-family models, are published
on [`Vineethsain/defenseclaw-system-one`](https://huggingface.co/spaces/Vineethsain/defenseclaw-system-one)
and appear nowhere here.

A model can be measured under both protocols. **The numbers across the two Spaces are
not interchangeable.** The corpora differ and the label sets differ.

## The deployment result

Re-thresholded so every arm blocks benign cases at the same rate as the incumbent cascade — a
block false-positive rate of {{fig:cap.value}} — the best arm in the cohort is
**`{{fig:cap.best.arm}}`** at recall **{{fig:cap.best.recall}}**: {{fig:cap.best.tp}} of
{{fig:corpus.positives}} positives, F1 {{fig:cap.best.f1}}. `{{fig:rank1.arm}}`, which leads on
discrimination, catches {{fig:cap.deberta.tp}} positive at the same budget.

Under a zero-false-positive gate, **{{fig:zfp.zero}} of the {{fig:zfp.candidates}} candidates
retain zero recall** — they catch nothing without blocking something benign. The best is
`{{fig:zfp.best.arm}}` at recall {{fig:zfp.best.recall}} over {{fig:zfp.best.tp}} true blocks.

No arm in this cohort reaches a recall at a deployable false-positive budget that would make it
useful on its own. Every threshold in those two gates is re-fitted, so none of those figures is
any arm's shipped behaviour, and neither gate is durable: when the System One programme measured
transfer to a disjoint corpus, 4 of 24 zero-FP gates survived and FPR caps held in 8 of 48.

## The ranking, on length-controlled AUC

Every arm is ranked on one fixed variable chosen by its class structure, never selected per arm,
and never on the excluded difference variable.

| # | Arm | lcAUC | Raw AUC | Shipped F1 | Block FPR |
| --- | --- | --- | --- | --- | --- |
| 1 | `{{fig:rank1.arm}}` | {{fig:rank1.lc}} | {{fig:rank1.raw}} | {{fig:deb.shipped}} | {{fig:deb.fpr}} |
| 2 | `{{fig:rank2.arm}}` | {{fig:rank2.lc}} | — | — | — |
| 3 | `{{fig:rank3.arm}}` | {{fig:rank3.lc}} | — | — | — |

`results.html` carries all {{fig:arms.scored}} rows with tp/fp/fn/tn, precision, recall, F1 and
block FPR at both operating points.

Rank 1 ran at a {{fig:rank1.cap}}-token cap with {{fig:rank1.shrunk}} rows shrunk. Ranks 2 and 3
ran at cap {{fig:rank2.cap}} with no rows shrunk, so they earned their positions seeing the whole
prompt while rank 1 did not.

{{fig:beat.control}} of the {{fig:arms.candidates}} candidates score above the untrained
`control-modernbert-base`. {{fig:under.band}} fall below the chance band, which puts them
anti-correlated with the label.

## What an untrained backbone scores

`control-modernbert-base` has no trained head and no safety training. Its best F1 on its own
scalar is {{fig:ctrl.oracle}} and its shipped F1 is {{fig:cb.f1}}, and it blocks {{fig:cb.fp}}
benign cases against {{fig:deb.fp}} for the highest-ranked candidate.

This is not leakage: the leakage gate put both controls at chance once prompt length is controlled
for, and this one lands at {{fig:cb.controlled}} inside the band [{{fig:band.lo}},
{{fig:band.hi}}]. It is the threshold sweep. An unconstrained best-F1 search on a corpus carrying
a length cue worth AUC {{fig:cue.tokens}} flatters anything correlated with length, and this
readout correlates with length at Spearman {{fig:cb.spearman}}. Several arms in this cohort cannot
be separated from an untrained backbone by F1.

## The corpus

| Property | Value |
| --- | --- |
| Corpus | s2, the core parity grid |
| Cases | {{fig:corpus.cases}} |
| Scorable | {{fig:corpus.scorable}} |
| Positives | {{fig:corpus.positives}} (grade A {{fig:corpus.gradeA}} + grade B {{fig:corpus.gradeB}}) |
| Benign | {{fig:corpus.negatives}} (grade D) |
| Excluded | {{fig:corpus.gradeC}} (grade C, diagnostic only) |
| Prevalence | {{fig:corpus.prevalence}} |
| Grid cell | C7 / I3 / Q2, `--instruction-format structured` |
| `cases_sha256` | `{{fig:corpus.sha}}` |

Grade C is excluded because the grade records an unresolved or partial adjudication, so a scored
decision on one of those cases would have no settled truth value. Every F1, AUC, FPR and confusion
matrix here is over the {{fig:corpus.scorable}} scorable cases.

## The two baselines

- **The trivial floor.** Blocking every case scores block-only F1 **{{fig:floor.f1}}** at
  {{fig:corpus.prevalence}} prevalence (tp {{fig:floor.tp}} / fp {{fig:floor.fp}} / fn
  {{fig:floor.fn}} / tn {{fig:floor.tn}}), at block FPR {{fig:floor.fpr}}. An F1 at or below the
  floor says the operating point is broken. **{{fig:arms.under.floor}} of the
  {{fig:arms.candidates}} candidates score below it, and {{fig:arms.zero.f1}} score exactly zero
  at their own argmax.**
- **The length cue.** Counting variables containing no model reach AUC {{fig:cue.tokens}}. Every
  arm carries a length-controlled AUC beside its raw AUC over five prompt-length quintiles. The
  pure length counter falls to {{fig:cue.tokens.controlled}} under that control.

The 95% chance interval for {{fig:corpus.positives}} positives and {{fig:corpus.negatives}}
negatives is [{{fig:band.lo}}, {{fig:band.hi}}] under Hanley and McNeil.

## Not in this revision

**No transfer figure.** {{fig:s3.arms}} arms are scored on a held-out corpus whose positives are
{{fig:s3.gradeA.share}} grade A against s2's {{fig:s2.gradeA.share}}. A difference between the two
conflates threshold miscalibration with a changed definition of a positive, so it is not a
generalisation test and no transfer penalty is published. The composition and the per-grade
separation are published instead.

`{{fig:arms.noshipped}}` is ranked and has both deployment gates but no shipped-argmax row, because
its prediction body landed after the run that recorded those.

## Disclosures

- {{fig:roster.gated}} of {{fig:roster.n}} arms need a licence-accepted HuggingFace token, across
  {{fig:roster.groups}} separate acceptance groups.
- All {{fig:roster.encoder}} trained encoder classifiers are
  `DebertaV2ForSequenceClassification`: three checkpoints inside one backbone family. The only
  independent encoder backbone is ModernBERT, and both ModernBERT arms are controls.
- Llama Guard 3 1B's shipped template hardcodes {{fig:lg.categories}} categories and none covers
  code execution or system damage. A custom category built from the I3 policy was used through the
  template's documented hook, with `llamaguard_default_taxonomy_covers_task: false` recorded.
- Qwen3 at 0.6B, 1.7B and 4B was dropped on a non-China provenance constraint.
- Both Falcon3 arms are licence `other`, the Falcon LLM licence.
- `P(block) − P(confirm)` is never ranked on: it inverted below chance on a disjoint corpus.
- In-sample best F1 is an oracle upper bound and is labelled as one wherever it appears.
- Rank 1's 510-token cap re-rendered {{fig:trunc.rows}} of {{fig:trunc.rowstotal}} rows
  ({{fig:trunc.rowspct}}) to fit, losing context the model never saw. The separate row-level field
  named `truncated` is true for {{fig:trunc.flagrows}} rows ({{fig:trunc.flagpct}}) and records a
  corpus request-build flag that is identical across every arm including the cap-6144 controls.
  The two are different measurements.
- The cohort runner writes neither `complete` nor `prediction_sha256`. A settlement step retrofits
  both and re-verifies, with two residual limits: the digest is taken at settlement over the
  body's complete-line prefix, so it certifies unchanged-since-settlement; and settlement requires
  {{fig:settle.rows}} untorn rows, so an unsettled metadata file means incomplete.
  {{fig:settle.settled}} of {{fig:arms.scored}} ranked arms are settled with a matching digest.
- The CPU throughput and memory figures are archived rather than reproducible: the measurement
  scripts were never saved and only their logs survive.
- Aggregates only. No per-case row detail is published. `mcptox` and
  `augur_unsafe_tool_input_eval` contribute aggregate numbers only.

## Pages

| Page | What it covers |
| --- | --- |
| `index.html` | Scope, the deployment result, the ranking, and what is measured. |
| `baselines.html` | The trivial floor, the length cue, the quintile stratification, the chance band. |
| `results.html` | Deployability at both gates, the full ranking, the untrained-backbone comparison, per-arm confusion metrics, the leakage gate, scorer equivalence, and rank 1's 512-token window. |
| `roster.html` | All {{fig:roster.n}} arms with licence, origin and gating group; encoder backbone families; taxonomy coverage; the Qwen3 drop. |
| `footprint.html` | CPU memory and throughput, the caveats, the two multimodal parameter splits. |
| `methodology.html` | Corpus and grade split, the two deployment gates, the held-out hold-out, scorer equivalence, oracle labelling, ranking-variable rules, run validity, publication scope. |
| `reproduce.html` | Every script and artifact, deep-linked to branch `feat/system-one-benchmarks`. |

The four data repositories holding the corpora and the prediction files are private. This Space
carries no corpus rows, no provider rationales, no credentials and no unredacted identifiers.
