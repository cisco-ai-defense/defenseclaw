---
title: SLM tool-call security
emoji: 🔧
colorFrom: gray
colorTo: green
sdk: static
app_file: index.html
pinned: false
license: other
short_description: 22 small models graded on blocking destructive tool calls
tags:
{{ui:card_tags}}
models:
{{ui:card_models}}
---

# SLM tool-call security

**No.** The best local model under 6B parameters, `{{fig:cap.f1.model}}`, blocks {{fig:cap.f1.tp}}
of {{fig:corpus.positives}} destructive tool calls at {{fig:cap.maxfp}} false blocks in
{{fig:corpus.negatives}} benign calls (block false-positive rate {{fig:cap.exact}}). None of the
{{fig:roster.n}} models is usable as a block decision at that budget.

Open `index.html` for the leaderboard: every model at the same budget, ordered by F1, sortable
and filterable.

| At block FPR ≤ {{fig:cap.exact}} | Value |
| --- | --- |
| Best F1 among {{fig:models.candidates}} candidates | `{{fig:cap.f1.model}}`, F1 {{fig:cap.f1}} |
| Its recall, with Wilson 95% interval | {{fig:cap.f1.recall}} [{{fig:res.wilson.lo}}, {{fig:res.wilson.hi}}] |
| Its precision | {{fig:cap.f1.precision}} |
| Best pair of models inside the budget | {{fig:over.half.tp}} of {{fig:corpus.positives}} caught |
| Candidates catching nothing with zero false blocks allowed | {{fig:zfp.zero}} of {{fig:zfp.candidates}} |
| Blocking every call, for reference | F1 {{fig:floor.f1.exact}} at block FPR 1 |

## Scope

Small local models on one corpus. The DefenseClaw cascade guardrail models and the Jev-family
models are on [`Vineethsain/defenseclaw-system-one`](https://huggingface.co/spaces/Vineethsain/defenseclaw-system-one).
**The numbers across the two Spaces are not interchangeable.** The corpora and label sets differ.

## Data

Corpus s2: {{fig:corpus.scorable}} scorable cases, {{fig:corpus.positives}} positive (grade A or
grade B) and {{fig:corpus.negatives}} benign, `cases_sha256 {{fig:corpus.sha}}`. Every grade comes
from one deterministic function, `{{fig:labels.fn}}()`. A second corpus exists whose positives are
{{fig:s3.gradeA.share}} grade A against s2's {{fig:s2.gradeA.share}}, so no score is compared
across the two.

Aggregates only. No per-case row detail is published; the case rows are evaluation-only and the
data repositories stay private. Source licences and redistribution markers are in
`{{fig:lock.path}}`.

## Pages

| Page | What it covers |
| --- | --- |
| `index.html` | The answer, the leaderboard, the findings and what they rest on. |
| `operating-point.html` | Every model at the budget: counts, intervals, zero-false-positive gate, size, sources, accuracy, pairs. |
| `results.html` | AUC and length-controlled AUC, the length cue, default decisions, controls, calibration. |
| `datasets.html` | Corpus, labels, sources, the second corpus, licences, the model roster and laptop footprint. |
| `methodology.html` | Terms, rules, estimator, run validity, build gates, scripts and changelog. |
