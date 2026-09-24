# slm_toolcall - the laptop-class tool-call cohort

A second, narrower evaluation run alongside the System One board: **22 small locally-runnable
models** (20 candidate guard/instruct arms + 2 negative controls) scored on the System One
**s2** cell at the single parity grid `C7` / `I3` / `Q2`.

The question it answers is not "which model is best" but "can a laptop-class model do this at
all, once you control for the cues in the corpus". The honest answer is heavily qualified -
see the caveats in `scoring/README.md` before quoting any number from it.

| directory | what it holds | where it ran |
|---|---|---|
| `harness/` | The runner, the arm registry, the lane scripts, the weight download/manifest scripts. | Lightning studio, `laptopguard/` (4x H200) |
| `scoring/` | Cohort scoring behind a parity gate, the surface-cue/leakage diagnostic, the trivial baselines and final comparisons. | CPU dev host, `/home/ubuntu/cohort-scoring/` |

Row-level data and per-arm metas are archived to the private HuggingFace dataset
`Vineethsain/defenseclaw-slm-toolcall-v1`. Model weights are **not** archived - they are
re-downloadable from the repos and revisions pinned in
`harness/weights_manifest{,2,3,4}.json`.

## Two things that will bite a future reader

1. **Cohort metas carry neither `complete` nor `prediction_sha256`.** The System One driver
   emits both; `harness/score_arm.py` emits neither and never hashes the prediction body. So
   the usual completeness/integrity check does not apply to cohort arms - argue completeness
   from `rows` against the expected request count plus `errors == 0`, and record a digest at
   archive time rather than expecting one in the meta.
2. **The CPU/laptop measurements are not reproducible from this tree.** `harness/build_llamacpp.sh`
   builds the toolchain, but the scripts that actually produced the RSS and throughput numbers
   were never saved. Only their logs survive. See `harness/README.md`.
