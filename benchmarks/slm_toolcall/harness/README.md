# slm_toolcall/harness - the laptop-class tool-call cohort harness

Runs a cohort of small, locally-runnable guard/instruct models ("arms") over the System One
**s2** cell and records a full probability distribution per request, so the cohort can be
scored with exactly the same arithmetic as the board arms.

Every arm is pinned to the single parity cell `C7` / `I3` / `Q2` (`score_arm.py` filters to
`["C7"], ["I3"], ["Q2"]`). This harness widens the *model* axis, not the grid.

Originally `laptopguard/` on the Lightning studio.

## Scripts

| script | what it does |
|---|---|
| `score_arm.py` | The runner. Scores one arm over `sysone/agree/s2-cases.jsonl`, writing a JSONL prediction body plus a `.meta.json`. Takes `--arm`, `--cases`, `--out`, `--run-id`, `--device`, `--dtype`, `--max-requests`, `--token-budget`, `--max-batch`, `--cap`, `--threads`, `--progress-every`. Reads the protocol config from `sysone/agree/cfg/contexts-v1.json` and `questions-v1.json`, and imports request construction from the reference driver `benchmark_run_system_one.py` so request bytes match the board runs. Holds a `<out>.lock` containing its PID while running. |
| `arms.py` | The arm registry (see below). Pure data, imported by the others. |
| `analyse.py` | Scores prediction bodies with the house method - block-only and any-intervention lenses, threshold sweeps, Mann-Whitney AUC, length-controlled AUC, per-length-stratum AUC, best-F1, the operating point at OpenJev's FPR, and zero-FP gates. Takes `--cases`, `--out`, `--preds label=path=readout`, and `--validate-27b` to check itself against the published 27b numbers. Truth grades come from `sysone/benchmark_inventory_system_one_sources.py`. |
| `report.py` | Renders text tables from `analyse.py`'s JSON (`sys.argv[1]`). stdout only. |
| `settle.py` | **The settlement step** - see "Integrity" below. Walks `preds/*.jsonl`, and for every body with at least `EXPECT = 30310` complete lines writes `complete: true`, `rows` and `prediction_sha256` into its meta, then **re-reads the meta and re-hashes the body** so the pass is measured rather than asserted. Exits non-zero if any settled arm's on-disk digest disagrees with its meta. Bodies short of 30,310 lines, or with a torn final line, are reported `partial`/`TORN` and left unsettled. |
| `run_lane.sh` | Runs a list of arms sequentially, pinned to card 0. Args: lane name (logging only), token budget, max batch, then arm names. |
| `run_lane_card.sh` | Same, but takes the card number first. **Refuses card 3** - reserved for the nimble reshard replicas. Also exports `OMP_NUM_THREADS=4 MKL_NUM_THREADS=4 RAYON_NUM_THREADS=4` and `TOKENIZERS_PARALLELISM=false`; see "The thread budget" below. Appends to the per-arm log rather than truncating it, so a resume does not destroy the earlier attempt. |
| `run_when_free.sh` | Same, but polls `nvidia-smi` and starts an arm only once the card has at least `MINFREE` MiB free. Args: card, minfree, lane, arms. |
| `dispatch_all.sh` | **One** dispatcher for the whole cohort across all four cards, holding at most `PERCARD` (default 3) concurrent arms per card, dispatching in nearest-to-complete order so prefetched weights are already warm. Deliberately a single owner: four independent dispatchers each counting globally would collectively cap at `MAXPAR` instead of 4x it, and four orchestrators racing the same output files is a duplicate-writer hazard. |
| `dispatch2.sh` | Single-card version, at most `MAXPAR` concurrent arms. Refuses card 3. |
| `dispatch_card2.sh` | The **earlier** single-card dispatcher, superseded by `dispatch2.sh`. Kept because it is the one that exhibits the counting bug described below - it limits with `pgrep -c -f 'score_arm.py --arm'`. |
| `vacate_and_dispatch.sh` | Hands cards 0 and 1 back to the coordinator while keeping card 2 working. Stops the lane shells **by exact PID** so they cannot advance to a next arm, then stops only the `score_arm` processes whose `CUDA_VISIBLE_DEVICES` is 0 or 1 - reading each PID's `/proc/<pid>/environ` to decide - and explicitly keeps the rest. Finally clears the `preds/*.lock` files left behind so the dispatcher can reclaim those arms. Partial bodies plus `--resume` retain the rows already scored. |
| `download.py` … `download4.py` | Staged `snapshot_download` of the cohort weights into `weights/<repo_with_underscores>`, writing `weights_manifest{,2,3,4}.json` (`repo`, `revision`, `path`, `bytes`, `status`, and where available `licence`, `params`, `architectures`, `id2label`, `max_pos`, `error`). `download3.py`/`download4.py` use the cached HF token for the gated repos. |
| `build_llamacpp.sh` | Builds CPU-only `llama-bench`, `llama-quantize` and `llama-cli` from `ggml-org/llama.cpp`, and installs the `gguf` package into the laptop venv. This is the toolchain behind the CPU/laptop measurements. |
| `weights_manifest*.json` | The download records - which revision of which repo was actually fetched, and its byte size. |

## "Lane" is not a fixed set here

`LANE` is only a **logging label** passed to the three `run_*.sh` scripts. Nothing in this
directory hardcodes, validates or interprets lane names. The lane names used elsewhere in the
programme (`intent-real`, `intent-ablation`, `toolcall-labels`, `deterministic-real`, …) are
corpus/lane identifiers defined outside this harness; do not read them off these scripts.

## The arm registry

`arms.py` fields: `repo`, `revision`, `params`, `licence`, `origin`, `readout`, `note`,
`loader`, `gated`, plus `control` on the two controls. `key` and `path` are injected at load.

**20 candidate arms + 2 controls = 22**, which is the 22-arm sweep.

| arm | repo | params | licence | origin | readout | gated |
|---|---|---|---|---|---|---|
| `granite-guardian-3.1-2b` | ibm-granite/granite-guardian-3.1-2b | 2,533,531,648 | apache-2.0 | USA (IBM) | letter3 | no |
| `granite-guardian-3.2-3b-a800m` | ibm-granite/granite-guardian-3.2-3b-a800m | 3,298,793,472 | apache-2.0 | USA (IBM) | letter3 | no |
| `granite-4.0-1b` | ibm-granite/granite-4.0-1b | 1,631,750,144 | apache-2.0 | USA (IBM) | letter3 | no |
| `granite-4.0-micro` | ibm-granite/granite-4.0-micro | 3,402,836,480 | apache-2.0 | USA (IBM) | letter3 | no |
| `phi-4-mini-instruct` | microsoft/Phi-4-mini-instruct | 3,836,021,760 | mit | USA (Microsoft) | letter3 | no |
| `smollm2-1.7b-instruct` | HuggingFaceTB/SmolLM2-1.7B-Instruct | 1,711,376,384 | apache-2.0 | France/USA (HuggingFace) | letter3 | no |
| `smollm3-3b` | HuggingFaceTB/SmolLM3-3B | 3,075,098,624 | apache-2.0 | France/USA (HuggingFace) | letter3 | no |
| `olmo-2-1b-instruct` | allenai/OLMo-2-0425-1B-Instruct | 1,484,916,736 | apache-2.0 | USA (Ai2) | letter3 | no |
| `falcon3-1b-instruct` | tiiuae/Falcon3-1B-Instruct | 1,669,408,768 | other (Falcon LLM licence) | UAE (TII) | letter3 | no |
| `falcon3-3b-instruct` | tiiuae/Falcon3-3B-Instruct | 3,227,655,168 | other (Falcon LLM licence) | UAE (TII) | letter3 | no |
| `shieldstral-1.0-3b` | mistralai/Shieldstral-1.0-3B | 3,849,090,048 | apache-2.0 | France (Mistral) | shieldstral | no |
| `deberta-v3-prompt-injection-v2` | protectai/deberta-v3-base-prompt-injection-v2 | 184,423,682 | apache-2.0 | USA (ProtectAI) | seqcls | no |
| `llama-guard-3-1b` | meta-llama/Llama-Guard-3-1B | 1,498,482,688 | llama3.2 | USA (Meta) | llamaguard | **yes** |
| `shieldgemma-2b` | google/shieldgemma-2b | 2,614,341,888 | gemma | USA (Google) | shieldgemma | **yes** |
| `gemma-3-4b-it` | google/gemma-3-4b-it | 4,300,079,472 | gemma | USA (Google) | letter3 | **yes** |
| `llama-3.2-3b-instruct` | meta-llama/Llama-3.2-3B-Instruct | 3,212,749,824 | llama3.2 | USA (Meta) | letter3 | **yes** |
| `gemma-3-1b-it` | google/gemma-3-1b-it | 999,885,952 | gemma | USA (Google) | letter3 | **yes** |
| `llama-3.2-1b-instruct` | meta-llama/Llama-3.2-1B-Instruct | 1,235,814,400 | llama3.2 | USA (Meta) | letter3 | **yes** |
| `prompt-guard-2-86m` | meta-llama/Llama-Prompt-Guard-2-86M | 278,810,882 | other | USA (Meta) | seqcls | **yes** (separate acceptance group) |
| `prompt-guard-2-22m` | meta-llama/Llama-Prompt-Guard-2-22M | 70,830,722 | other | USA (Meta) | seqcls | **yes** (separate acceptance group) |
| `control-modernbert-base` | answerdotai/ModernBERT-base | 149,655,232 | apache-2.0 | USA/France (Answer.AI/LightOn) | mlm_control | no (**control**) |
| `control-modernbert-large` | answerdotai/ModernBERT-large | 395,881,664 | apache-2.0 | USA/France (Answer.AI/LightOn) | mlm_control | no (**control**) |

The 8 gated repos need licence acceptance on HuggingFace before `download3.py`/`download4.py`
can fetch them; `prompt-guard-2-*` sit in a *different* acceptance group from the other Meta
repos, so accepting `llama3.2` is not sufficient for them.

The two ModernBERT arms are **negative controls**, not candidates. They are masked-LM
readouts with no safety training, so any apparent skill they show is a surface cue rather
than detection - which is exactly what `../scoring/leakage.py` quantifies.

## Prediction body and meta schema

Body rows: `schema_version`, `run_id`, `case_id`, `event_index`, `model`, `model_revision`,
`context_variant`, `instruction_variant`, `question_variant`, `detected`, `action`,
`confidence`, `probabilities{}`, `answers{}`, `duration_ms`, `input_tokens`, `output_tokens`,
`context_bytes`, `context_events`, `truncated`, `route`, `request_sha256`, `context_sha256`,
and `error_code` when a row failed.

Meta (`<out>.meta.json`): `arm`, `repo`, `revision`, `readout`, `licence`, `origin`,
`params_declared`, `params_counted`, `device`, `dtype`, `cap_tokens`, `token_budget`,
`max_batch`, `buffer_requests`, `load_seconds`, `elapsed_seconds`, `rows_per_min`,
`temperature`, `softmax_support`, `duration_ms_semantics`, `cuda_alloc_gib`, `torch_threads`,
`letter_ids`, `rows`, `shrunk`, `batches`, `prompts`, `in_tokens`, `errors`, `resumed_from`,
plus readout-specific keys (`seqcls_id2label`, `yes_ids`, `no_ids`, …).

### Integrity: the runner does not write it, `settle.py` retrofits it

1. **`score_arm.py` writes neither `complete` nor `prediction_sha256`, and never hashes the
   prediction body.** The System One driver (`benchmark_run_system_one.py`) emits both inline.
   So a freshly-written cohort meta **cannot** satisfy the programme's rule — "meta says
   `complete: true` **and** on-disk sha256 equals `prediction_sha256`" — because neither field
   exists yet.

   **`settle.py` is the step that closes this**, and it must be run before a cohort arm is
   archived or cited. It computes the digest, writes both fields, then re-reads and re-hashes
   to confirm. Two caveats on the strength of the resulting guarantee:

   - The digest is computed **at settlement time, over the complete-line prefix of the body**
     (`settled_note` records this). It is not a digest the writer committed to while writing,
     so it certifies "this body has not changed since settlement", not "this body is exactly
     what the runner intended to emit". That is weaker than the System One driver's guarantee.
   - Settlement requires `rows >= 30310` and an untorn final line. An arm below that is
     reported `partial` and left unsettled — so an **unsettled** meta means incomplete, not
     merely unverified.

   An arm archived *before* `settle.py` runs is legitimately recorded as `UNVERIFIABLE`, and
   completeness then has to be argued from `rows` versus the expected request count plus
   `errors == 0`.
2. `duration_ms` is **batch wall time attributed to every row in that batch**, not per-row
   latency (the meta says so itself in `duration_ms_semantics`). Do not read it as
   per-request latency.

## The thread budget - why every dispatcher caps threads

`run_lane_card.sh`, `dispatch_all.sh`, `dispatch2.sh` and `dispatch_card2.sh` all export:

```
OMP_NUM_THREADS=4  MKL_NUM_THREADS=4  RAYON_NUM_THREADS=4  TOKENIZERS_PARALLELISM=false
```

This is not tuning, it is a fix. Per `run_lane_card.sh`'s own comment: 19 arms at torch's
default 48 OMP threads, plus a Rayon pool sized to all 96 cores, **exhausted the box's thread
budget to the point where it could no longer fork a login shell.** These arms are GPU-bound,
so the caps cost nothing. Do not remove them when adding arms.

## Counting running arms: `/proc`, not `pgrep -f`

`dispatch_all.sh` and `dispatch2.sh` count live arms by walking `/proc/[0-9]*`, matching
`comm` against `python*` and then checking `cmdline` for `score_arm.py`. `dispatch_all.sh`
additionally reads `/proc/<pid>/environ` to recover each process's `CUDA_VISIBLE_DEVICES` and
attribute it to a card.

They do this because **`pgrep -f 'score_arm.py'` also matches the operator's own monitoring
shells**, whose command lines contain the pattern. That inflates the count and stalls the
limiter, so arms stop being dispatched. `dispatch_card2.sh` is the superseded version that
still limits with `pgrep -c -f` and shows the bug.

This is the same self-match hazard that makes `pkill -f` dangerous, which is why
`vacate_and_dispatch.sh` stops processes by **exact PID** and never uses `pkill` or `killall`.

## The CPU/laptop measurements are not reproducible from this tree

`build_llamacpp.sh` builds the CPU benchmarking toolchain (`llama-bench`, `llama-quantize`,
`llama-cli`), but **no script in this harness invokes it or writes the CPU results.** The
CPU/laptop measurement outputs that exist on the studio - `cpu/rss_results.json`,
`cpu/rss_results2.json`, `cpu/rss_results3.json`, `cpu/rss2.log`, `cpu/bench_all.log`,
`cpu/convert_all.log`, `cpu/convert_all2.log`, `cpu/inventory.json`, `cpu/inventory2.json` -
were produced by ad-hoc invocations that were never saved to a file.

A studio-wide search for scripts referencing `rss_results`, `max_rss`, `ru_maxrss`,
`llama-bench` or `convert_hf_to_gguf` returned only `laptopguard/build_llamacpp.sh` (which
builds the tools but does not run them) and `sysone/kev-src/kev/train.py` (vendored upstream
training code, unrelated to CPU measurement). **No RSS or CPU-latency measurement script
exists anywhere on the studio outside `llama.cpp` itself and the venvs.**

So the CPU numbers are **archived as logs but not reproducible from vendored code.** If those
measurements matter going forward, the measurement step needs to be written down as a script.
Note also that `score_arm.py` measures only `cuda_alloc_gib`, `elapsed_seconds`,
`rows_per_min` and batch `duration_ms` - it measures no RSS and no CPU latency at all.

## Results this produced

Per-arm prediction bodies and metas under `laptopguard/preds/` on the studio, which — once
`settle.py` has settled them — are the input to `../scoring/score_cohort.py`,
`../scoring/leakage.py` and `../scoring/final.py`.

## Snapshot provenance

This is a snapshot of a **directory that was being actively edited while the sweep ran**, taken
from `/teamspace/studios/this_studio/laptopguard/` on 2026-09-24. Every file here was verified
sha256-identical to the studio copy at vendoring time.

Worth knowing if you diff against the studio later: `settle.py` and the four dispatcher scripts
were written *during* the sweep (02:48-03:20 UTC), after the first vendoring pass, and
`run_lane_card.sh` gained its thread caps mid-run. The dispatcher family in particular is an
evolution — `dispatch_card2.sh` then `dispatch2.sh` then `dispatch_all.sh` — and all three are
kept because the differences between them are the operational lessons, not noise.
