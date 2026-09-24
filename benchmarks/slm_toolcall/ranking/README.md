# ranking — the cohort ranking, and the estimator that was retracted

Ranks all 22 cohort arms on a **fixed** variable chosen by class structure, never selected per
arm. **Zero GPU**, read-only over settled prediction bodies. All arithmetic (`sweep`,
`best_point`, `mann_whitney_auc`, `f1_of`, `wilson`, `truth_grade`, `ACTION_RANK`) is imported
verbatim from
[`../../system_one/reproduce/07-analysis/rescoring/remine.py`](../../system_one/reproduce/07-analysis/rescoring/remine.py)
so a cohort figure and a board figure are the same code path.

Vendored from `defenseclaw-dev:/home/ubuntu/cohort-rank/`.

| script | what it does | writes |
|---|---|---|
| `rank_cohort.py` | Full cohort ranking over s2 and s3. | `artifacts/cohort-rank.json` |
| `reconcile.py` | Reconciles two independent length-controlled AUC rankings and tests whether each position survives a change of estimator. | rank-stability records |
| `analyse_rank.py` | Ranking table, headline-claim verification, and the s2 → s3 transfer arithmetic. | analysis tables |

## The ranking variable

`P(block)` for 3-class and dual-head arms; the single positive scalar for 2-class arms, which is
that arm's only block-analogue. **No per-arm variable selection happens anywhere in this
directory.** `P(block) − P(confirm)` is excluded by rule, not by result: it inverted below chance
on a disjoint corpus, so it is never ranked on.

## Read this before quoting `cohort-rank.json`

`cohort-rank.json` ranks on the **unweighted mean** of five within-quintile AUCs. That estimator
gives a length bin holding 2 of 436 positives the same weight as one holding 230 — about 20% of
the weight on 0.5% of the evidence. **It is retracted.** The published length-controlled AUC is
the **pair-weighted pooled** figure, which weights each bin by the comparisons it actually holds,
and it is produced by [`../s3/rank_authoritative.py`](../s3/README.md) into
`artifacts/cohort-length-controlled-ranking.json`.

Both artifacts are kept: the retraction is part of the record, and the Space's verifier holds a
retired literal so the unweighted figure cannot return to a page. `cohort-rank.json` also carries
a **partial** s3 block covering only 3 arms, written before the other 3 bodies landed; the 6-arm
pair (`s3-stats.json` + `s3-scores-in-scope.json`) governs, and the build asserts the two agree on
every arm they share — same ranking variable, same raw AUC to the last digit, same 100,001 rows,
same prediction digest, same argmax confusion matrix.

Neither position 1 nor position 2 is claimed as settled: the artifact records `rank_1_stable` and
`rank_2_stable` as false, each contradicted by one of the nine schemes `reconcile.py` tests.
Position 3 is contested across estimators and the artifact says so.

## Re-running

```bash
# inputs: settled s2 (and optionally s3) prediction bodies, plus the cases files
python3 rank_cohort.py
python3 reconcile.py
python3 analyse_rank.py
```

Input paths are module constants at the top of each file, written against `/home/ubuntu/...` on
the dev host. Bodies restore from `hf://datasets/Vineethsain/defenseclaw-slm-toolcall-v1`
(`predictions/`, `predictions-s3/`); corpora from
`hf://datasets/Vineethsain/defenseclaw-system-one-corpora-v1`.
