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
| `run_lane.sh` | Runs a list of arms sequentially, pinned to card 0. Args: lane name (logging only), token budget, max batch, then arm names. |
| `run_lane_card.sh` | Same, but takes the card number first. **Refuses card 3** - that card was reserved for the nimble reshard replicas. |
| `run_when_free.sh` | Same, but polls `nvidia-smi` and starts an arm only once the card has at least `MINFREE` MiB free. Args: card, minfree, lane, arms. |
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

### Two schema gaps worth knowing before you verify anything

1. **The cohort meta has no `complete` field and no `prediction_sha256` field**, and
   `score_arm.py` never hashes the prediction body. The System One driver
   (`benchmark_run_system_one.py`) *does* emit both. So the standard
   "meta says `complete: true` and on-disk sha256 equals `prediction_sha256`" check
   **cannot be applied to cohort arms** - there is nothing to check it against. Completeness
   for a cohort arm has to be argued from `rows` vs expected request count and `errors == 0`.
2. `duration_ms` is **batch wall time attributed to every row in that batch**, not per-row
   latency (the meta says so itself in `duration_ms_semantics`). Do not read it as
   per-request latency.

## The CPU/laptop measurement scripts are not here - and were not preserved

`build_llamacpp.sh` builds the CPU benchmarking toolchain, but **no script in this harness
runs it or writes the CPU results.** The CPU/laptop measurement outputs that exist on the
studio - `cpu/rss_results.json`, `cpu/rss_results2.json`, `cpu/rss_results3.json`,
`cpu/rss2.log`, `cpu/bench_all.log`, `cpu/convert_all.log`, `cpu/convert_all2.log`,
`cpu/inventory.json`, `cpu/inventory2.json` - were produced by ad-hoc invocations that were
never saved to a file. A search of the studio for any script referencing `rss_results`,
`max_rss`, `ru_maxrss`, `llama-bench` or `convert_hf_to_gguf` found nothing outside
`llama.cpp` itself and the venvs.

So the CPU numbers are **archived as logs but not reproducible from vendored code.** If those
measurements matter going forward, the measurement step needs to be written down as a script.
Note also that `score_arm.py` measures only `cuda_alloc_gib`, `elapsed_seconds`,
`rows_per_min` and batch `duration_ms` - it measures no RSS and no CPU latency at all.

## Results this produced

Per-arm prediction bodies and metas under `laptopguard/preds/` on the studio, which are the
input to `../scoring/score_cohort.py`, `../scoring/leakage.py` and `../scoring/final.py`.
