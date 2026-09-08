# DefenseClaw deterministic benchmarks

This directory contains the public benchmark harness, schemas, dataset lock,
normalizers, authored conformance fixtures, and published scorecard for
DefenseClaw's deterministic guardrails.

All external sources are publicly accessible and revision-pinned in
[`datasets.lock.json`](datasets.lock.json). Source records are downloaded into
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

- Go 1.24 or newer
- Python 3.11 or newer
- `git`
- `pyarrow` and `jsonschema` for Parquet-backed datasets
- AWS credentials only when reproducing the optional offline GPT-OSS labeling
  stage; no model is used at runtime

## Run the smoke suite

```bash
go run ./benchmarks/cmd/defenseclaw-benchmark run \
  --corpus benchmarks/fixtures/smoke.jsonl \
  --dataset-lock benchmarks/datasets.lock.json \
  --profiles default,permissive,strict \
  --gate \
  --output outputs/benchmarks/smoke

go run ./benchmarks/cmd/defenseclaw-benchmark verify \
  --output outputs/benchmarks/smoke
```

The runner writes case-level predictions, environment and policy inventories,
aggregate metrics, corpus and dataset manifests, and checksums.

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
