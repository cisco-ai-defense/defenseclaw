# DefenseClaw benchmarks

Three separate evaluation programmes live here. They share the dataset lock, the grade
function and most of the scoring arithmetic, and they answer different questions — so a number
from one is **not** comparable with a number from another.

| programme | question | entry point | published |
|---|---|---|---|
| **Deterministic guardrails** (this file, below) | Do the shipped deterministic rules detect what they claim, and how noisy are they on benign trajectories? | this README | [`DETERMINISTIC-DETECTION-BENCHMARKS.md`](DETERMINISTIC-DETECTION-BENCHMARKS.md), [`results/public-scorecard-v1.json`](results/public-scorecard-v1.json) |
| **System One** cascade | What is the best production architecture for `deterministic → System One → Gemma`, on a governed 1,000 → 10,000 → 100,000 funnel? | [`system_one/HANDOFF.md`](system_one/HANDOFF.md), [`system_one/reproduce/`](system_one/reproduce/) | Space [`Vineethsain/defenseclaw-system-one`](https://huggingface.co/spaces/Vineethsain/defenseclaw-system-one) |
| **SLM tool-call cohort** | Can a laptop-class local model decide that a tool call must be blocked, at a false-positive budget a deployment would accept? | [`slm_toolcall/README.md`](slm_toolcall/README.md) | Space [`Vineethsain/defenseclaw-slm-toolcall`](https://huggingface.co/spaces/Vineethsain/defenseclaw-slm-toolcall) |

Cross-programme context, the corpora as built, the two baselines every number is read against,
and the findings that were withdrawn: [`EXPERIMENTS.md`](EXPERIMENTS.md).
Current status, what is published versus withheld, where the data lives and what is still open:
[`HANDOFF-2026-09-24.md`](HANDOFF-2026-09-24.md).

**Row-level data is never committed.** Every corpus row, prediction body and run meta lives in
private HuggingFace datasets; this repository holds code, aggregate artifacts and documentation
only. The restore map is in the handoff.

---

## Deterministic guardrails

This directory contains the public benchmark harness, schemas, dataset lock,
normalizers, authored conformance fixtures, and published scorecard for
DefenseClaw's deterministic guardrails.

The separate [`llm_judge/`](llm_judge/) lane runs local Ollama models through
DefenseClaw's production `LLMJudge` request, shipped rule-pack prompts, JSON
parser, and verdict mapping. It combines those predictions with the same
datasets and deterministic engine used by this benchmark. Tool-risk training
and protected corpora are outside this lane.

Sources used by the published public suite are publicly accessible and
revision-pinned in [`datasets.lock.json`](datasets.lock.json). The lock may also
track candidate sources that are not admitted to a published score. Source records are downloaded into
an ignored local data directory and are not committed. The harness never
executes commands or tool calls from a dataset.

## What is measured

The suite reports three different kinds of evidence separately:

1. **Binary accuracy:** TP, TN, FP, FN, precision, recall, F1, and FPR where
   independently usable positive and negative truth exists.
2. **Benign noise:** finding FPR and block rate on honest agent trajectories.
3. **Coverage/conformance:** detector reach on contextual data and exact
   positive/hard-negative behavior for authored grammars. These are not
   population F1 estimates.

`balanced` is the published name for the runtime `default` profile. It is an
alias, not a fourth experimental arm.

## Requirements

- Go 1.26.4 or the exact version declared by `go.mod`
- Python 3.11 or newer
- `git`
- `pyarrow` and `jsonschema` for Parquet-backed datasets
- AWS credentials only when reproducing the optional offline GPT-OSS labeling
  stage; no model is used at runtime

## Run the smoke suite

```bash
test -z "$(git status --porcelain)"
benchmark_commit="$(git rev-parse --verify HEAD)"
go build -buildvcs=true -trimpath \
  -ldflags "-X main.buildCommit=$benchmark_commit -X main.buildDirty=false" \
  -o bin/defenseclaw-benchmark ./benchmarks/cmd/defenseclaw-benchmark

./bin/defenseclaw-benchmark run \
  --corpus benchmarks/fixtures/smoke.jsonl \
  --dataset-lock benchmarks/datasets.lock.json \
  --profiles default,permissive,strict \
  --gate \
  --output outputs/benchmarks/smoke

./bin/defenseclaw-benchmark verify \
  --output outputs/benchmarks/smoke

./bin/defenseclaw-benchmark verify --publication \
  --output outputs/benchmarks/smoke
```

The runner writes case-level predictions, environment and policy inventories,
aggregate metrics, corpus and dataset manifests, and checksums.
It refuses to evaluate a corpus unless the selected worktree is clean and the
running binary contains clean, embedded VCS metadata matching its exact
40-hex repository commit. The explicit linker values above support linked Git
worktrees where Go omits `vcs.*` build settings even with `-buildvcs=true`;
native Go build metadata takes precedence when present. Publication verification remains
backward-compatible with older bundles that predate binary provenance fields.

## Run an opt-in policy pack

Opt-in policy packs are separate benchmark lanes, not additional runtime
profiles. Select them by their repository name; each runs with the balanced
(`default`) action posture and is reported under an `opt-in/<name>` label:

```bash
./bin/defenseclaw-benchmark run \
  --corpus benchmarks/fixtures/cloud-production-conformance-v1.jsonl \
  --dataset-lock benchmarks/datasets.lock.json \
  --profiles default \
  --opt-in-packs cloud-production-protection \
  --output outputs/benchmarks/cloud-production-conformance

./bin/defenseclaw-benchmark verify \
  --output outputs/benchmarks/cloud-production-conformance

./bin/defenseclaw-benchmark verify --publication \
  --output outputs/benchmarks/cloud-production-conformance
```

Supported names are `cloud-production-protection`,
`database-destruction-protection`, `infrastructure-destruction-protection`,
`kubernetes-production-protection`, and `privacy-high-assurance`. The output
environment records each lane's policy digest, policy root, and action posture.
Standard `default`, `permissive`, and `strict` runs are unchanged when
`--opt-in-packs` is omitted.

## Prepare public sources

Set an ignored data root and download only the sources needed for a run:

```bash
export BENCHMARK_DATA_DIR="$PWD/.benchmark-data"

python benchmarks/scripts/benchmark_prepare.py \
  --lock benchmarks/datasets.lock.json \
  --data-dir "$BENCHMARK_DATA_DIR" \
  --datasets atomic-red-team,nl2bash,shell-attack-evolution,tldr
```

Preparation verifies the pinned revision and declared paths. Adapters then
project the minimum executable representation into
[`schema/case-v1.schema.json`](schema/case-v1.schema.json):

```bash
python benchmarks/scripts/benchmark_normalize.py \
  --lock benchmarks/datasets.lock.json \
  --data-dir "$BENCHMARK_DATA_DIR" \
  --datasets atomic-red-team,nl2bash,shell-attack-evolution,tldr \
  --split validation \
  --output "$BENCHMARK_DATA_DIR/public-command-validation.jsonl"
```

Dedicated adapters in [`scripts/`](scripts/) cover MonitoringBench,
LinuxArena, TerminalBench, ISETrace, ATBench, InjecAgent, AgentDojo, Ylemis,
and the other public trajectory sources listed in the lock.

## Optional offline labeling

The public-command truth construction used GPT-OSS batch inference only as an
offline proposal stage. It did not participate in detector execution. The
reproducible scripts are:

- `benchmark_label_bedrock.py`: prepares, submits, and collects structured
  batch judgments for public normalized cases;
- `benchmark_apply_labels.py`: joins judgments by stable case ID;
- `benchmark_finalize_proof_labels.py`: accepts deterministic-malicious truth
  only when a literal standalone effect is present;
- `benchmark_label_trajectory_bedrock.py` and
  `benchmark_finalize_trajectory_proofs.py`: perform the equivalent bounded
  trajectory proposal/finalization flow.

No human adjudication was used. Source-label and model-correlated error are
therefore limitations. A source-level attack label is never copied onto every
tool call. Dynamic operands, missing identity, uncertain result status,
conditional execution, and incomplete chains remain contextual or out of
scope.

## Published results

- Human-readable report:
  [`DETERMINISTIC-DETECTION-BENCHMARKS.md`](DETERMINISTIC-DETECTION-BENCHMARKS.md)
- Machine-readable scorecard:
  [`results/public-scorecard-v1.json`](results/public-scorecard-v1.json)
- Public docs page: `docs-site/content/docs/benchmarks.mdx`

The report explains the datasets, labeling contract, metrics, profile behavior,
detector changes, limitations, and complete replication procedure.

## System One architecture benchmark

The opt-in System One lane compares deterministic guardrails, Jev, OpenJev,
Von, and the production-path Gemma judge without changing runtime policy. It
uses a governed `1,000 -> 10,000 -> 100,000` funnel: broad development
screening, family-disjoint validation and culling, then a frozen final scale
run. Exact-proof, contextual-trajectory, benign-only, protected three-way, and
diagnostic truth remain separate scoring lenses.

Run the non-network tests with:

```bash
make system-one-benchmark-test
```

The checked-in protocol is under `benchmarks/system_one/`. Before a paid run,
`benchmark_inventory_system_one_sources.py` produces a value-free source
catalog and exact stage quotas. `benchmark_prepare_system_one.py` creates
family-disjoint stage corpora, `benchmark_run_system_one.py` runs the typed
System One contract, and `benchmark_score_system_one.py` writes quality,
calibration, latency, cost, Pareto, and machine-readable culling evidence.

Prediction artifacts contain IDs, typed probabilities, confidence, routes,
durations, token counts, and hashes only. They omit state, prompts, provider
responses, rationales, credentials, and evidence values. Restricted source
payloads remain referenced by immutable revision and digest instead of being
copied into the experiment archive.

The runs that were actually executed, stage by stage, are vendored under
[`system_one/reproduce/`](system_one/reproduce/): corpus and serving setup, the analysis and
re-mining lane (`07-analysis/`), the Space generator (`08-site-build/`), the chunked reshard that
recovered the `bespoke-nimble-9b` held-out cell (`09-reshard/`), and the staging, payload guard and
upload tooling that moved the evidence into the private datasets (`10-archive/`).

## SLM tool-call cohort

22 small locally-runnable models — 20 candidates and 2 negative controls — scored on the same
`C7` / `I3` / `Q2` cell, reported at one shared block false-positive rate so the columns are
comparable down the table. See [`slm_toolcall/README.md`](slm_toolcall/README.md) for the corpora,
the harness, the run coverage (including which arms have the held-out 100,001-row bodies), and the
end-to-end commands.
