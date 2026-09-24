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
| `ranking/` | The cohort ranking on a fixed per-class variable, rank stability across estimators, and the estimator that was retracted. | CPU dev host, `/home/ubuntu/cohort-rank/` |
| `s3/` | The held-out corpus: scoring, the escalation/power analysis, DeLong variance, the authoritative length-controlled ranking. | CPU dev host, `/home/ubuntu/s3-escalation-2026-09-24/` |
| `site-build/` | The generator, payload guard, verifier and publisher for the public HuggingFace Space. | Built anywhere; **published only from the dev host**, because the payload guard needs the corpora. |
| `artifacts/` | The vendored scoring artifacts every published figure is read from. | — |

Nothing in `ranking/`, `s3/` or `scoring/` uses a GPU: they are read-only over prediction bodies
that already exist, and all their arithmetic is imported from
`../system_one/reproduce/07-analysis/rescoring/remine.py` rather than reimplemented.

## The corpora

| | s2 (scoring) | s3 (held out) |
|---|---|---|
| cases / scorable | 4,277 / 3,817 | 24,476 / 24,476 |
| positives | 436 (A 17, B 419) | 221 (A 193, B 28) |
| benign | 3,381 | 24,255 |
| prevalence | 11.42% | 0.903% |
| grade A share of positives | 3.90% | **87.33%** |
| prediction rows per arm | 30,310 | 100,001 |
| arms scored | 22 | 6 |
| `cases_sha256` | `39f2c1df…1adbf7` | `0ccbc08f…69fa03` |

Zero case-id overlap. The grade mixes are nearly inverted, so **no score on one corpus is
compared with a score on the other** anywhere in this programme. See [`s3/README.md`](s3/README.md)
for what that rules out and what is published instead.

## Where the results are

| | where |
|---|---|
| Public report | **[`Vineethsain/defenseclaw-slm-toolcall`](https://huggingface.co/spaces/Vineethsain/defenseclaw-slm-toolcall)** — 11 pages, all 22 arms at one shared false-positive budget, sortable leaderboard, glossary |
| Figures the Space reads | `artifacts/*.json` in this directory |
| Build record | `site-build/site/_build-figures.json` — every headline at full precision, plus the sha256 of every artifact the build read |
| Row-level bodies, metas, manifests | private dataset **`Vineethsain/defenseclaw-slm-toolcall-v1`** (1.12 GiB, 248 files) |
| Corpora | private dataset **`Vineethsain/defenseclaw-system-one-corpora-v1`** |

Model weights are **not** archived — they are re-downloadable from the repos and revisions pinned
in `harness/weights_manifest{,2,3,4}.json`.

## How to run it end to end

```bash
# 1. weights (GPU host)
python3 harness/download.py                      # + download2/3/4.py for later tranches

# 2. inference, one lane per card (Lightning studio, laptopguard/)
bash harness/run_lane.sh 0 98304 48 <arm> <arm> ...          # s2
python3 harness/score_arm.py --arm <arm> \
        --cases <s3 cases.jsonl> --out preds-s3/<arm>.jsonl \
        --run-id lg-s3-<arm> --device cuda --dtype bfloat16   # s3

# 3. settle — NOT optional, see caveat 1 below
python3 harness/settle.py

# 4. score, rank, analyse (CPU, zero GPU)
python3 scoring/score_cohort.py                  # -> artifacts/cohort-scores.json
python3 scoring/leakage.py                       # -> artifacts/leakage-diagnostic.json
python3 scoring/final.py                         # -> artifacts/final-comparisons.json
python3 ranking/rank_cohort.py                   # -> artifacts/cohort-rank.json  (see ranking/README.md)
python3 s3/rank_authoritative.py                 # -> the PUBLISHED ranking
python3 s3/extract.py && python3 s3/score_s3.py && python3 s3/stats_s3.py

# 5. publish the Space (dev host only — the payload guard needs the corpora)
SLM_COHORT=artifacts python3 site-build/build.py
SPACE_DATA=<corpora root> SPACE_PROTO=<protocol root> python3 site-build/publish.py
```

Each script carries its input paths as module constants at the top, written against
`/home/ubuntu/...` on the dev host; point them at wherever the bodies were restored.

## Coverage: what was actually run

All 22 arms have a settled s2 body (30,310 rows each, 0 errors). **6 of the 22 also have a
settled s3 body at 100,001 rows over all 24,476 cases**, and they include the top three of the
published ranking:

`deberta-v3-prompt-injection-v2` (rank 1) · `shieldgemma-2b` (2) ·
`granite-guardian-3.2-3b-a800m` (3) · `shieldstral-1.0-3b` (8) · `prompt-guard-2-22m` (11) ·
`prompt-guard-2-86m` (14)

Two cautions on that sentence, both expanded in [`s3/README.md`](s3/README.md):

- **"100k" is a row count, not a case count.** 100,001 rows = one per (case, event) over 24,476
  cases. The staged plan in `../system_one/HANDOFF.md` calls stage S3 a "100,000-case final
  scale"; that is not what was built.
- **"Top three" is ambiguous here.** The three arms leading the *operating-point leaderboard*
  (best F1 at the shared budget) are `falcon3-1b-instruct`, `granite-4.0-micro` and
  `granite-4.0-1b`, and **none of those has an s3 body**. Ranking position and leaderboard
  position are different questions and do not pick the same arms.

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
