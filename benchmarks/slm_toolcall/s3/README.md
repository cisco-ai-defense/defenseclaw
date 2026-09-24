# s3 — the held-out corpus, and the escalation question

Scoring and analysis for the **held-out corpus s3**, read-only over prediction bodies that were
already settled. **Zero GPU, zero new inference**: every number these scripts produce is derived
from rows that already exist. All arithmetic is imported from
[`../../system_one/reproduce/07-analysis/rescoring/remine.py`](../../system_one/reproduce/07-analysis/rescoring/remine.py)
rather than reimplemented, so a figure here and the same figure on the System One board are the
same code path.

Vendored from `defenseclaw-dev:/home/ubuntu/s3-escalation-2026-09-24/`.

## The corpus

| property | s2 (scoring) | s3 (held out) |
|---|---|---|
| cases | 4,277 | 24,476 |
| scorable | 3,817 (460 grade C excluded) | 24,476 (no grade C) |
| positives | 436 — grade A 17, grade B 419 | 221 — grade A 193, grade B 28 |
| benign (grade D) | 3,381 | 24,255 |
| prevalence | 11.42% | 0.903% |
| grade A share of positives | 3.90% | **87.33%** |
| `cases_sha256` | `39f2c1df…1adbf7` | `0ccbc08f…69fa03` |
| case-id overlap with the other | 0 | 0 |

s3 is a genuinely disjoint corpus, not a resample. **Its positives are built from almost the
opposite grade mix**, which is why no score measured on one corpus is compared with a score
measured on the other anywhere in this programme. That is a corpus-design property, not a
result, and more data of the same kind does not fix it.

## What "100k" means here

Each arm's s3 prediction body is **100,001 rows**, one row per (case, event) pair over all
24,476 cases, with 0 errors and 0 cases missing. It is a row count, not a case count. The
staged plan in [`../../system_one/HANDOFF.md`](../../system_one/HANDOFF.md) calls stage S3 a
"100,000-case final scale"; what was actually built and run is a 24,476-case corpus that yields
~100k prediction rows per arm. **Anyone quoting "100k" should say which.**

## Coverage: 6 of the 22 cohort arms

| arm | rank on s2 | rows | cases | errors | settled |
|---|---|---|---|---|---|
| `deberta-v3-prompt-injection-v2` | **1** | 100,001 | 24,476 | 0 | yes |
| `shieldgemma-2b` | **2** | 100,001 | 24,476 | 0 | yes |
| `granite-guardian-3.2-3b-a800m` | **3** | 100,001 | 24,476 | 0 | yes |
| `shieldstral-1.0-3b` | 8 | 100,001 | 24,476 | 0 | yes |
| `prompt-guard-2-22m` | 11 | 100,001 | 24,476 | 0 | yes |
| `prompt-guard-2-86m` | 14 | 100,001 | 24,476 | 0 | yes |

Rank is position on the published length-controlled AUC ranking. **The top three of that
ranking all have a complete, settled s3 body.** Every one carries `complete: true` and a
`prediction_sha256` that still matches the bytes on disk.

The three arms that lead the **operating-point leaderboard** — highest F1 at the shared
false-positive budget — are `falcon3-1b-instruct`, `granite-4.0-micro` and `granite-4.0-1b`, and
**none of those has an s3 body**. The two orderings are different questions and they do not pick
the same arms. Which "top three" a claim is about has to be stated.

## The scripts

| script | what it does |
|---|---|
| `extract.py` | Caches per-case aggregates from the settled rows so the rest of the directory does not re-read 500 MB per question. Read-only. |
| `score_s3.py` | Task 1: the six cohort arms with a settled s3 counterpart. Task 2: `bespoke-nimble-9b` on s3 as a System One board row, kept out of every cohort ranking. Writes `artifacts/s3-scores-in-scope.json`. |
| `stats_s3.py` | Task 3, the escalation question: **is s3 large enough to separate the top three?** DeLong variance is primary (exact, closed form); a paired stratified bootstrap runs alongside as an independent cross-check. Also: what dropping the worst arms would buy. Writes `artifacts/s3-stats.json`. |
| `delong.py` | DeLong variance/covariance for correlated ROC AUCs, pure Python — the dev host has no numpy, so the placement functions use `bisect` over sorted arrays. The kernel is the same tie-corrected psi as `remine.mann_whitney_auc`, so the AUC it recovers equals the published one. |
| `rank_authoritative.py` | The **authoritative** length-controlled AUC ranking for the 22 s2 arms, and the reason `cohort-rank.json`'s ranking is retracted: that artifact ranks on the *unweighted mean* of five within-quintile AUCs, which gives a bin holding 2 of 436 positives the same weight as one holding 230. The published figure is the pair-weighted pooled estimator. |
| `bench_task4.py` | Task 4: what other benchmarks these 22 models support. Computes — with zero new inference — the cascade/triage frontier on s2 and on s3, and calibration (reliability tables, ECE, MCE, Brier). **Most of this is computed and not published**; see below. |

## Computed but not published

These scripts produce more than either Space shows. Deliberately withheld, and each is in the
verifier's retired-literal list so it cannot reappear in prose by accident:

- **any transfer penalty** (s3 oracle best − s3 at the s2-fitted threshold), e.g. 0.2616 for
  rank 1;
- **s3 F1 at the s2-fitted threshold**, and s3 shipped block-only F1;
- **overall s3 raw AUC per arm** (only the per-grade separation AUCs are published);
- any generalisation claim in either direction.

The reason is the grade-composition inversion above: a difference between the two corpora
conflates a miscalibrated threshold with a changed definition of a positive. What **is**
published is the composition itself, the per-grade separation (grade-A AUC, grade-B AUC, A − B,
and caught counts at an in-sample oracle threshold, labelled as such), the settlement record for
all six bodies, and the power analysis. See `results.html#corpora` and `datasets.html#settlement`
on the Space.

One finding in `s3-scores-in-scope.json` that is **not** on either Space and is worth a decision:
`reconciliation.fact_1_auc_and_f1_orderings_invert`. ShieldGemma orders s3 far better than
DeBERTa (raw AUC 0.8955 against 0.6335) while their oracle F1 inverts (0.4565 against 0.1208),
because AUC is rank-based and prevalence-free while F1 at 0.903% prevalence is dominated by
precision. The artifact records the verdict as "CONFIRMED, and it is not a bookkeeping error".

## Re-running

The bodies are read-only inputs; nothing here needs a GPU.

```bash
# inputs: settled s3 prediction bodies + the s3 cases file
#   bodies : hf://datasets/Vineethsain/defenseclaw-slm-toolcall-v1 -> predictions-s3/
#   cases  : hf://datasets/Vineethsain/defenseclaw-system-one-corpora-v1 -> corpora/s3/
python3 extract.py          # cache per-case aggregates first
python3 score_s3.py         # -> s3-scores-in-scope.json
python3 stats_s3.py         # -> s3-stats.json
python3 rank_authoritative.py
```

Each script carries its own input paths at the top as module constants (they were written
against `/home/ubuntu/...` on the dev host). Point them at wherever the bodies were restored;
none of them writes to its inputs.

To produce a **new** s3 body for an arm that does not have one, the runner is in
[`../harness/score_arm.py`](../harness/score_arm.py) and takes the corpus as an argument:

```bash
python3 ../harness/score_arm.py --arm <arm> \
  --cases  <s3 cases.jsonl> \
  --out    preds-s3/<arm>.jsonl \
  --run-id lg-s3-<arm> \
  --device cuda --dtype bfloat16 --cap 6144
python3 ../harness/settle.py           # retrofits complete + prediction_sha256, then verifies
```

`harness/run_lane.sh` hardcodes the s2 output path, so it drives s2 only; an s3 lane means
calling `score_arm.py` directly as above. Settlement is **not optional** — an unsettled body
cannot satisfy the programme's integrity rule and must not be cited.
