# Contextual LLM-as-judge benchmark

This lane measures Google Gemma using the exact DefenseClaw runtime judge
path. Granite was removed from the active matrix after development and
holdout pilots showed materially lower recall than Gemma. The Go harness calls
`LLMJudge.RunToolJudge` or `LLMJudge.RunJudges`, loads the selected shipped rule pack, sends the
request through Bifrost, requests deterministic JSON output, parses the
runtime schema, maps findings to runtime severity/action, and merges stateful
event verdicts with the production merge function.

The benchmark never executes a dataset command. Prediction artifacts omit
payloads, prompt text, model responses, rationales, and evidence values.

## Dataset policy

The public source families match the deterministic detection work and are
pinned in
[`datasets.lock.json`](datasets.lock.json):

| Lane | Dataset | Truth use |
| --- | --- | --- |
| Primary coding hard negatives | pinned, successful TerminalBench trajectories plus task instructions | Public trajectory and per-hook alert/block rates |
| Private coding hard negatives | access-controlled coding-session traces | Local-only benign FPR and block/interruption rate |
| Primary contextual attacks | MonitoringBench real-argument trajectory prefixes | High-confidence trajectory detection, block recommendation, latency, and tokens |
| Visible malicious commands | labeled BashBench | Medium-confidence diagnostic coverage only |
| Context diagnostic | HF agentic red-team real arguments | Diagnostic only; atomic rows inherit trajectory membership |

Tool-risk training and protected tool-risk evaluation corpora are explicitly
excluded. Low-confidence projected atomic events are also excluded from F1:
an ordinary `ls` call does not become independently detectable merely because
it occurred inside a malicious trajectory.

Development data may be used to improve prompts and thresholds. Freeze the
code and rule pack before evaluating validation. Never tune on test data.

## Model matrix

| Model | Runtime | Role |
| --- | --- | --- |
| `gemma4:12b-mlx` | Local MLX/Ollama-compatible endpoint | Local quality and private-data lane |
| `bedrock/google.gemma-4-26b-a4b` | Amazon Bedrock online | Hosted quality and public scale lane |
| `bedrock/google.gemma-3-12b-it` | Amazon Bedrock online/batch | Lower-cost hosted comparison |

Qwen 3.5 and Granite are excluded by benchmark policy. Muse Glimmer is excluded
from the default matrix because its smallest local artifact is too large for
repeated runs on the 24 GB benchmark host.

## Build a stable corpus

Inputs must already be normalized case-v1 JSONL. Selection is stable by seed,
family-deduplicated, and supports per-surface quotas. For example:

```bash
python3 benchmarks/scripts/benchmark_prepare_contextual_judge.py \
  --input /private/benign-development.jsonl \
  --input /private/bashbench-development.jsonl \
  --input /private/monitoringbench-development.jsonl \
  --input /private/agentic-red-team-development.jsonl \
  --quota private-benign:benign:action:100 \
  --quota AISafety-Student/labeled-bashBench:attack:action:50 \
  --quota neur26anonsub/ctrldataset2026:attack:action:50 \
  --quota hf-agentic-red-team:attack:action:25 \
  --output outputs/contextual-judge/development.jsonl \
  --extended-lock-output outputs/contextual-judge/datasets.lock.json
```

Medium-confidence BashBench and low-confidence agentic red-team rows are
diagnostic and do not affect F1 unless independent visible evidence upgrades
their truth. The frozen primary lane uses task-family-deduplicated TerminalBench
trajectories as benign truth and family-excluded MonitoringBench trajectories
as attack truth.

TerminalBench task instructions must be joined into `payload.content` before
running the judge. The harness replays that content through
`ObserveSessionPrompt`, then replays the trajectory through the same
`RunToolJudge` calls used in production:

```bash
/usr/bin/python3 benchmarks/scripts/benchmark_add_terminalbench_context.py \
  --source-root "$TERMINAL_BENCH_TRAJECTORIES" \
  --input outputs/contextual-judge/terminalbench.jsonl \
  --task-root "$TERMINAL_BENCH_TASKS" \
  --tasks-revision "$TERMINAL_BENCH_TASKS_REVISION" \
  --output outputs/contextual-judge/terminalbench-with-context.jsonl
```

## Run deterministic and production-path judge predictions

Run the normal deterministic benchmark against the same corpus and default
profile. Then invoke the gated Go harness once per model. The wrapper below
selects Bedrock profile authentication or the local Ollama-compatible endpoint
and always executes the exact production judge path:

```bash
benchmarks/scripts/benchmark_run_judge.sh \
  outputs/contextual-judge/development.jsonl \
  outputs/contextual-judge/gemma4-12b-mlx.jsonl \
  gemma4:12b-mlx
```

The generated metadata records model, corpus digest, rule pack, call count,
wall time, temperature, JSON mode, and exact runtime path. Use `-timeout 120m`
for long local runs. Interrupted sequential runs can resume a validated prefix with
`DEFENSECLAW_JUDGE_BENCHMARK_RESUME=1`; add
`DEFENSECLAW_JUDGE_BENCHMARK_RETRY_FAILURES=1` to discard the first failed row
and its suffix before resuming.

For a hosted provider, bounded concurrency preserves the same runtime path
while increasing throughput:

```bash
DEFENSECLAW_JUDGE_BENCHMARK_CONCURRENCY=16 \
  benchmarks/scripts/benchmark_run_judge.sh \
  outputs/contextual-judge/validation.jsonl \
  outputs/contextual-judge/bedrock-gemma4-26b-a4b.jsonl \
  bedrock/google.gemma-4-26b-a4b
```

Concurrency is bounded to 1–64 and defaults to 1. Results are still written in
corpus order, so prefix resume remains safe. Bedrock also supports API-key,
IAM-environment, and instance-role auth through the normal DefenseClaw provider
configuration.

## Bedrock batch lane

Amazon Bedrock Batch supports `google.gemma-3-12b-it` and is useful for a bulk
quality/robustness pass over the full private corpus. It is not the primary
production-fidelity lane: Bedrock Batch does not support structured output or
`response_format`, while the live DefenseClaw judge requests JSON mode. A batch
run must therefore use the identical system/user prompts and production parser,
record `recordId` for stable joins, and be reported separately as
`batch_without_response_format`. Do not merge its parse-failure rate or quality
metrics into the exact online result.

The exact online Bedrock run is the release gate. Batch is the inexpensive
large-N supplement for false-positive and attack-family coverage. Both send
private prompt/tool-call content to AWS and require explicit data-governance
approval and a selected in-region S3 bucket before submission.

## Score standalone and combined posture

```bash
python3 benchmarks/scripts/benchmark_score_contextual_judge.py \
  --cases outputs/contextual-judge/development.jsonl \
  --deterministic-predictions outputs/contextual-judge/deterministic/predictions.jsonl \
  --llm-predictions outputs/contextual-judge/gemma.jsonl \
  --output outputs/contextual-judge/scorecard.json
```

The scorecard reports confusion matrices, precision, recall, F1, macro F1,
FPR, Wilson 95% intervals, benign block rate, attack block recall, dataset
slices, incremental LLM catches, invocation rate, prompt/completion tokens,
judge failures, JSON-mode rate, and latency p50/p95/max. Prediction rows also
record total, alerted, and blocked hook decisions. The scorecard reports these
as operational activity rather than per-decision accuracy because stateful
truth labels the whole trajectory. Hosted token prices can be supplied
explicitly; local Ollama monetary cost is otherwise left unestimated rather
than treated as free.

## Claim boundaries

Use “benchmark-bounded detection coverage,” not universal protection. A judge
`block` is an intervention recommendation only when an enabled synchronous
pre-tool hook consumes it. EventRouter tool judging is asynchronous and
observational, so its result cannot be described as prevented execution.

For coding sessions, prefer a deterministic-first `regex_judge` cascade. It
preserves exact local blocking, avoids an LLM call when deterministic evidence
is decisive, and sends unresolved calls to the contextual judge. `judge_first`
is useful as an upper-bound quality measurement but incurs model latency on
every call.

Run the non-network tests with `make contextual-judge-test`.

The frozen local holdout results and Bedrock scale-out projection are recorded
in [`results-2026-09-09.md`](results-2026-09-09.md).
