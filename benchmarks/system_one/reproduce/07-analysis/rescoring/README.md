# 07-analysis/rescoring - re-mining s2, and the held-out designs

Read-only re-scoring of already-settled System One prediction artifacts. No GPU, no provider
calls: every script here consumes prediction bodies plus the case file and recomputes
aggregates. Run on the CPU dev host, not the studio.

`remine.py` holds the arithmetic; everything else imports it or reuses it verbatim, so the
comparisons across passes are like-for-like by construction.

## The two AUC definitions - label every AUC A or B

`remine.py` defines **two** aggregation definitions, and they are **not interchangeable**.
Both take a per-case decision from per-event probabilities, but they aggregate in a
different order:

**Definition A** - aggregate each probability class across events first, then combine:

| variable | A |
|---|---|
| `risk` | `1 - min_events(P(allow))` |
| `block` | `max_events(P(block))` |
| `sum` | `max_events(P(block)) + max_events(P(confirm))` |
| `diff` | `max_events(P(block)) - max_events(P(confirm))` |

**Definition B** - combine per event first, then take the max over events:

| variable | B |
|---|---|
| `risk` | `max_events(1 - P(allow))` |
| `block` | `max_events(P(block))` |
| `sum` | `max_events(P(block) + P(confirm))` |
| `diff` | `max_events(P(block) - P(confirm))` |

`risk` and `block` are identical under both definitions. **`sum` and `diff` are not** - for
those two, A and B are genuinely different numbers and a figure quoted without its
definition letter is unusable.

`P(block) - P(confirm)` is the variable that **inverted below chance** on the disjoint s3
corpus (OpenJev `0.856982` -> `0.299402`, definition B). It is carried through the code as a
flagged variable, and nothing should ever be ranked on it. See the dataset cards.

## Scripts

| script | what it does | writes |
|---|---|---|
| `enumerate_core.py` | Discovery. Walks every `*.jsonl.meta.json` under `/home/ubuntu/.system-one-data/outputs` and lists the artifacts whose meta pins the 4,277-case core scoring corpus (`cases_sha256` `39f2c1df...`). | stdout only |
| `remine.py` | First pass. Re-mines 12 model arms on s2: per-case aggregation under A and B, threshold sweeps, AUC / F1 / precision / recall, zero-FP gates, FPR-capped operating points, for four ranking variables. | `<--out>/corpus.json`, `<--out>/remine-full.json` |
| `remine_extra.py` | Second pass over additional artifacts pinned to the same 4,277-case corpus: Jev at other question tiers (`q0`,`q1`,`q3`,`q4`), the deterministic rule tier, DiffusionGemma, and secjudge variants. Reuses `remine.py`'s arithmetic unchanged. | `<--out>/remine-full.json` |
| `remine_kev.py` | Third pass: `kev-9b` on s2 at the parity grid `C7`/`I3`/`Q2`. The body is staged read-only from the studio at `kev-s2/kev-9b-shard0.jsonl`. | `<--out>/remine-full.json` |
| `transfer_s2_to_s3.py` | **The primary held-out design.** Fits a threshold on s2 (3,817 scorable cases, 436 positive = **11.42%** prevalence) and evaluates it on s3 (24,476 cases, 0.90% prevalence) with disjoint case IDs. Because prevalence differs sharply, the overfitting penalty is measured as *s3 oracle F1 minus s3 F1 at the s2-fitted threshold* - not against the s2 in-sample number. Also transfers FPR caps and zero-FP gates. | `heldout-s2-to-s3.json` |
| `cv_within_s2.py` | **The secondary, weaker design.** Grouped, label-stratified k-fold CV inside s2 (k=5 and k=10). Groups by case ID truncated to the first two `/`-separated segments; folds assigned round-robin over `sha256(case_id)` order separately for positives and negatives, so it is reproducible. Weaker than `s2 -> s3` because the corpus is the same and only the rows differ - it is labelled as such in the output. | `heldout-s2-cv.json` |

## Gate and cap survival

- `remine.py` `zero_fp_point()` finds the lowest threshold with `fp == 0` and reports the
  true positives retained, a Wilson 95% CI, and the rule-of-three upper bound.
- `remine.py` `at_fpr_cap()` reports max recall under `FPR_CAPS = [0.00384502, 0.005]`.
- `transfer_s2_to_s3.py` reports, per transfer, `s3_gate_still_zero_fp` and
  `s3_false_positives_leaked` - i.e. whether an s2-fitted zero-FP gate *stays* zero-FP on s3.
- `cv_within_s2.py` reports `folds_still_zero` and `fp_leaked_pooled`.

Headline survival numbers (carried in the dataset cards): **zero-FP gates survived 4 of 24
s2 -> s3 transfers; FPR caps 8 of 48.**

## Results these produced

| result file | produced by |
|---|---|
| `out/remine-full.json`, `out/corpus.json` | `remine.py` |
| `out-extra/remine-full.json` | `remine_extra.py` |
| `out-kev/remine-full.json` | `remine_kev.py` |
| `heldout-s2-to-s3.json` | `transfer_s2_to_s3.py` |
| `heldout-s2-cv.json` | `cv_within_s2.py` |

`heldout-summary.tsv`, `remine-combined.json`, `remine-all-arms-by-variable.tsv` and
`inventory.json` also sit in the working directory, but **no script in this directory writes
them** - they were produced by ad-hoc combine/flatten steps that were not preserved as files.
They are archived as artifacts; treat them as derived views of the JSON above rather than as
reproducible outputs, and regenerate from the JSON if you need them.

## Caveats that travel with these numbers

- In-sample best-F1 is an **oracle upper bound**, not a result.
- Never rank on `P(block) - P(confirm)`; it inverted below chance out of sample.
- Every AUC must be labelled **A** or **B**.
- The corpus carries a **~0.77-AUC length cue** with no model at all (prompt tokens
  `0.7692264380822134`, event count `0.7772553177633239`), so arm comparisons should be
  length-controlled. `../../../slm_toolcall/scoring/leakage.py` measures this directly.
- Blocking every case scores block-only F1 `0.20503174229955326` at 11.42% prevalence. That
  is the floor any shipped operating point has to clear.
