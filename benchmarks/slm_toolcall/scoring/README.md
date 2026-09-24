# slm_toolcall/scoring - scoring the cohort, and the diagnostics that qualify the result

Read-only scoring of the cohort prediction bodies. Run on the CPU dev host
(`/home/ubuntu/cohort-scoring/`). The arithmetic is imported **verbatim** from
`../../system_one/reproduce/07-analysis/rescoring/remine.py`, so cohort numbers and board
numbers are directly comparable.

Inputs are `/home/ubuntu/.system-one-data/outputs/s2/cases.jsonl` for truth, plus the
prediction bodies in `/home/ubuntu/cohort-scoring/preds/`.

| script | what it does | writes |
|---|---|---|
| `score_cohort.py` | Scores the cohort arms with the house method, behind a parity gate (below). Three-key arms get all four ranking variables under definitions A and B; two-class arms emit a single positive-class scalar, so they get one ranking variable and one AUC (A and B **coincide by construction** for those). Also carries the DeBERTa 512-token truncation analysis: reconstructs the per-row truncation flag, stratifies errors by truncated vs untruncated, and computes AUC within each stratum. | `cohort-scores.json` |
| `leakage.py` | The surface-cue diagnostic. Computes AUC from **pure structural cues with no model at all** - `natural_prompt_tokens` (max and sum over events), `context_bytes` (max), `context_events`, `event_count_in_prediction` - under `structural_cue_auc`. Then, per control, the Spearman correlation between the control's score and natural prompt length, and AUC **within length quintiles** to strip the length cue out. Finally the Pearson agreement between the two controls. | `leakage-diagnostic.json` |
| `final.py` | Trivial baselines and headline comparisons: `block_every_case` and allow-everything floors, the Hanley-McNeil AUC null band at A=0.5, length-controlled AUC within quintiles for DeBERTa and the anchor variables, and DeBERTa vs anchor / vs OpenJev / vs the oracle ceiling. | `final-comparisons.json` |

## The parity gate

`score_cohort.py` will not report a cohort arm until it has re-derived three **reference**
arms from their settled bodies and matched the published numbers:

| reference | body | published block-only F1 | also checked |
|---|---|---|---|
| OpenJev (reference) | `s2/openjev-final.jsonl` | `0.70231214` | - |
| `open-jev-qwen-2b` (on-dev settled) | `openjev-qwen/s2/open-jev-qwen-2b.jsonl` | `0.17194570135746606` | confusion `(tp,fp,fn,tn) = (57,170,379,3211)` |
| `open-jev-qwen-27b` | `openjev-qwen/s2/h200-settled/open-jev-qwen-27b.jsonl` | `0.33206107` | confusion `(87,1,349,3380)`, AUC `P(block) || defA` = `0.9480285133598713` |

It records `abs_delta_f1`, `confusion_matches_published`, and
`auc_agrees_within_5e-12` into `report["parity_gate"]`. The point is that the scoring code is
proven against known answers before it is trusted on new arms - a disagreement here means the
scoring changed, not that the new arm is interesting.

(If you are looking for something called the "stage-0 gate": this parity gate is the only gate
in this directory. Nothing here uses the label "stage-0", so don't cite that name against
this code.)

## What the diagnostics actually establish

These are not decoration - they are the reason the cohort numbers cannot be read as a
leaderboard:

- **There is a ~0.77-AUC length cue in the corpus with no model at all**: prompt tokens
  `0.7692264380822134`, event count `0.7772553177633239`. Any arm scoring in that band has
  demonstrated nothing. Arm comparisons must be length-controlled, which is what the
  quintile-stratified AUC in `leakage.py` and `final.py` is for.
- **Blocking every case scores block-only F1 `0.20503174229955326`** at 11.42% prevalence.
  Five board arms sit below that floor at their shipped operating point. An arm that cannot
  beat "block everything" is not a detector.
- **The two ModernBERT arms are negative controls** - bare masked-LM heads with no safety
  training. Whatever they score is the cue floor, not skill.
- **In-sample best-F1 is an oracle upper bound**, not a result. It is reported because the
  gap between it and the transferred number is the quantity of interest.
- **`P(block) - P(confirm)` inverted below chance out of sample** (OpenJev `0.856982` ->
  `0.299402`, definition B, on the disjoint s3 corpus). `score_cohort.py` flags whether the
  best variable is this one, and `final.py` labels it `[FLAGGED VARIABLE]` under both
  definitions. Never rank on it.
- **Every AUC must be labelled A or B.** Variable names in the output carry the definition
  (e.g. `P(block) || defA`). For two-class arms the two definitions coincide; for
  `sum` and `diff` variables they genuinely differ. See
  `../../system_one/reproduce/07-analysis/rescoring/README.md` for the two formulas.
- **DeBERTa has a hard 512-token architectural limit**, so a large share of s2 cases are
  truncated. The truncation-stratified AUC in `score_cohort.py` is what tells you whether its
  score survives on the cases it could actually see.

## Results these produced

`cohort-scores.json`, `leakage-diagnostic.json`, `final-comparisons.json` in
`/home/ubuntu/cohort-scoring/`, archived to the private
`defenseclaw-slm-toolcall-v1` dataset.
