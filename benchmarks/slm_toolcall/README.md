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

## Three things that will bite a future reader

1. **Integrity is a two-step process here, and the second step is not optional.**
   `harness/score_arm.py` writes neither `complete` nor `prediction_sha256` and never hashes
   the prediction body, so a freshly-written cohort meta cannot satisfy the programme's
   integrity rule. **`harness/settle.py` retrofits both fields and re-verifies them**, and must
   be run before an arm is archived or cited. An unsettled meta means the arm is incomplete
   (settlement requires 30,310 untorn rows), not merely unchecked. Note that the retrofitted
   digest is computed at settlement time, so it certifies "unchanged since settlement" rather
   than "as the runner emitted it" — weaker than the System One driver's inline guarantee.
2. **The CPU/laptop measurements are not reproducible from this tree.** `harness/build_llamacpp.sh`
   builds the toolchain, but the scripts that actually produced the RSS and throughput numbers
   were never saved anywhere on the studio. Only their logs survive. See `harness/README.md`.
3. **Never count running arms with `pgrep -f`, and never use `pkill`.** The pattern matches the
   operator's own monitoring shells, which stalls the dispatcher's concurrency limiter. The
   dispatchers walk `/proc` instead; `harness/vacate_and_dispatch.sh` stops processes by exact
   PID. Also keep the `OMP/MKL/RAYON_NUM_THREADS=4` caps — without them the box ran out of
   threads and could not fork a login shell. Both are documented in `harness/README.md`.
