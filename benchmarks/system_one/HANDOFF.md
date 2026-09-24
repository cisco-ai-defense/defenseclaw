# DefenseClaw System One Benchmark Handoff

> **Superseded as a status record.** The plan and protocol below still hold. The "Active runs",
> "Immediate next steps", GPU-worker and cost sections describe 2026-09-21 and are out of date. For
> what ran, what is published, where the data is and what is still open, see
> [`../HANDOFF-2026-09-24.md`](../HANDOFF-2026-09-24.md).

Status captured: 2026-09-21. This document is the operational handoff for continuing the Jev/OpenJev/Von guardrail benchmark in Claude Code.

## Objective

Find the best production architecture for improving DefenseClaw guardrail quality, latency, and cost while preserving exact deterministic decisions. The primary hypothesis is:

```text
deterministic guardrails -> Jev/System One -> Bedrock Gemma 4
```

Deterministic findings and blocks must never be downgraded. System One should resolve cheap contextual decisions, and only uncertain or high-impact cases should reach the LLM.

The canonical detailed plan is also available locally at:

```text
/Users/vnarajal/.devin/plans/plan-c77cfa92b40e8a3c.md
```

## Full staged plan

### Stage S1: 1,000-case broad screen

- Use development-only, family-deduplicated cases.
- Current selection: 40 grade-A exact/outcome-backed, 410 grade-B contextual trajectories, 150 grade-C diagnostics, and 400 grade-D benign rows.
- Screen context variants, instruction variants, question decompositions, Jev/OpenJev/Von backends, and cascade policies.
- Reject schema failures, deterministic downgrades, benign-block regressions, future-context leakage, unstable variants, and Pareto-dominated configurations.
- Retain at most three Jev operating candidates, one OpenJev candidate, one Von candidate if valid, and permanent deterministic/Gemma baselines.

### Stage S2: 10,000-case confirmation

- Use disjoint families: approximately 8,000 development-confirmation and 2,000 frozen validation rows.
- Run only S1 survivors and permanent baselines.
- Freeze context, questions, thresholds, retries, cache semantics, and routing before validation.
- Balanced gate: reduce Gemma invocation by at least 25%, preserve deterministic decisions, have no benign-block regression, materially improve latency or cost, and keep unsafe-recall regression within one point of deterministic -> Gemma.
- Retain at most two or three finalists.

### Stage S3: 100,000-case final scale

- Use untouched test/operational families and frozen finalists only.
- Do not tune or cull based on S3 results.
- Report separate lenses:
  - grade A exact/outcome-backed quality;
  - grade B complete-trajectory contextual quality;
  - grade D production-weighted benign/noise/cost lane;
  - grade C/E diagnostic or OOD coverage;
  - optional protected TS-Bench three-way aggregate after all policy is frozen.
- At least 10,000 independently benign decisions are required before a low-FPR claim.

### Context experiments

- `C0`: current call only.
- `C1`: authenticated user intent plus current call.
- `C2`: intent plus last one call.
- `C3`: intent plus last three calls.
- `C7`: production-bounded intent plus last seven calls and current call.
- `CR`: at most three deterministically relevant priors.
- `CS`: C7 content represented as structured JSON.
- `CF`: bounded full-prefix diagnostic.
- `CA`: runtime-available value-minimized ActionFacts.
- `CD`: data-minimized/redacted context.

Also run causal pairs: relevant versus unrelated history, authorizing versus non-authorizing intent, incomplete versus complete chains, failed versus successful predecessors, and matching versus mismatched identity.

### Instruction experiments

Jev has no chat-system role. Its equivalent is typed question instruction/criteria engineering:

- `I0`: concise Jev-native instructions.
- `I1`: compact DefenseClaw policy.
- `I2`: long LLM-prompt adaptation diagnostic.
- `I3`: compact policy plus boundary semantics.

### Question experiments

- `Q0`: direct allow/confirm/block Choice.
- `Q1`: decomposed atomic Nouls.
- `Q2`: Choice plus risk Score plus context-sufficiency Noul.
- `Q3`: eight current DefenseClaw tool-security categories.

Arithmetic, identity joins, time windows, outcomes, and final policy remain code-owned.

### Final outputs

Produce Pareto frontiers and three operating points:

- safety-max;
- balanced;
- low-cost/latency.

Report quality, calibration, per-hook and per-trajectory latency, cold/warm behavior, provider calls, cache rates, token/GPU cost, failures, and external context bytes.

## Branches and commits

Local repository:

```text
/Users/vnarajal/Desktop/defenseclaw-1
branch: feat/system-one-benchmarks
```

`feat/acp-guard` was restored exactly to `origin/feat/acp-guard` at `5775a811c`. Do not put benchmark commits back on that branch.

Local benchmark commits:

```text
81919bc99 fix(benchmarks): harden large provider stages
5219d8283 fix(benchmarks): make provider runs resumable
ba40d1797 docs(benchmarks): define private evidence policy
f7f81395d fix(benchmarks): expose stage quota intersections
36365205a feat(benchmarks): evaluate System One guardrail cascades
```

The local worktree should be clean except for unrelated untracked `.codex-patches/`. Never stash, delete, stage, or modify `.codex-patches/`.

AWS clone:

```text
/home/ubuntu/defenseclaw-system-one
branch: feat/system-one-benchmarks
current remote-clone commit: 63200b9bb64d
worktree: clean
```

The AWS commit hashes differ because commits were transferred with `git format-patch | git am`. Remote log:

```text
63200b9b harden large provider stages
07e1b56f make provider runs resumable
ddd0825d define private evidence policy
de1ccab6 expose stage quota intersections
1243cf3c add System One benchmark
```

Nothing has been pushed.

## Implemented files

```text
benchmarks/system_one/pilot-v1.json
benchmarks/system_one/questions-v1.json
benchmarks/system_one/contexts-v1.json
benchmarks/system_one/hf-data-policy.json
benchmarks/system_one/hf-dataset-card.md
benchmarks/schema/system-one-prediction-v1.schema.json
benchmarks/scripts/benchmark_inventory_system_one_sources.py
benchmarks/scripts/benchmark_prepare_system_one.py
benchmarks/scripts/benchmark_run_system_one.py
benchmarks/scripts/benchmark_score_system_one.py
benchmarks/scripts/test_benchmark_inventory_system_one_sources.py
benchmarks/scripts/test_benchmark_prepare_system_one.py
benchmarks/scripts/test_benchmark_run_system_one.py
benchmarks/scripts/test_benchmark_score_system_one.py
```

`Makefile` has `system-one-benchmark-test`; `benchmarks/README.md` documents the lane.

Verification completed:

```text
make system-one-benchmark-test  # 15 tests pass after hardening
ruff check                      # passes
remote focused tests            # pass
```

## SSH and host access

### DefenseClaw development controller

From the local machine:

```bash
ssh defenseclaw-dev
cd /home/ubuntu/defenseclaw-system-one
```

Controller details:

```text
EC2: i-02a1ef0c909e16d3b
region/AZ: us-east-1 / us-east-1a
instance: m8i-flex.4xlarge
project: /home/ubuntu/defenseclaw-system-one
data: /home/ubuntu/.system-one-data
Python benchmark venv: /home/ubuntu/.system-one-venv
Von venv: /home/ubuntu/.von-venv
```

### GPU worker

From `defenseclaw-dev`:

```bash
ssh -i ~/.ssh/defenseclaw-system-one-gpu \
  -o StrictHostKeyChecking=yes \
  ubuntu@43.202.158.42
```

GPU details:

```text
EC2: i-000ceb2251b5ebe55
region/AZ: ap-northeast-2 / ap-northeast-2b
instance: g6e.8xlarge On-Demand
price observed: $5.56762/hour
GPU: NVIDIA L40S, 46,068 MiB reported
public/private IP: 43.202.158.42 / 172.31.17.142
root EBS: vol-05043b832944418ce, 200 GiB encrypted gp3
security group: sg-0d8f2262d29e098d8
SSH source: 100.63.212.49/32 only
host-key fingerprint: SHA256:Jbb3PWJGdfuHdbjNJ4ET4lz65QEnsvU+3I5gunKYojI
```

The dedicated security group was created rather than modifying the default SG. SSH host key is pinned in `~/.ssh/known_hosts` on the controller.

OpenJev services on GPU:

```text
vLLM: 127.0.0.1:8000
shim: 127.0.0.1:3000
model: /opt/openjev-model
venv: /opt/openjev-venv
vLLM log: /var/log/openjev-vllm.log
shim log: /home/ubuntu/openjev-shim.log
vLLM PID observed: 4320
shim PID observed: 6502
```

Controller SSH tunnel:

```text
127.0.0.1:3000 -> GPU 127.0.0.1:3000
PID file: ~/.system-one-openjev-tunnel.pid
log: ~/.system-one-openjev-tunnel.log
```

Health checks:

```bash
curl http://127.0.0.1:3000/v1/version
ssh -i ~/.ssh/defenseclaw-system-one-gpu -o StrictHostKeyChecking=yes \
  ubuntu@43.202.158.42 \
  'curl http://127.0.0.1:8000/v1/models; nvidia-smi'
```

The GPU is currently running and billable. Stop it immediately after OpenJev inference. Stopping is reversible. Ask the user before terminating the instance or deleting `vol-05043b832944418ce` or `sg-0d8f2262d29e098d8`.

Stop command from local machine:

```bash
aws ec2 stop-instances --profile devops --region ap-northeast-2 \
  --instance-ids i-000ceb2251b5ebe55
```

## Authentication and secrets

- Hugging Face identity is configured on both local/controller as `Vineethsain`.
- Jev credential is stored only on the controller in:

```text
~/.config/defenseclaw/system-one.env
mode: 600
```

Use:

```bash
. ~/.config/defenseclaw/system-one.env
```

Never print, copy into documentation, upload, commit, or echo the key. The credential pasted earlier in chat must not be copied from chat; the controller file is the operational secret source.

- AWS local controller profile: `devops`.
- The GPU worker uses the existing instance profile and can also be managed through SSM in `ap-northeast-2`.

## Data and artifact locations

```text
/home/ubuntu/.system-one-data/deterministic-labels
/home/ubuntu/.system-one-data/deterministic-benchmark
/home/ubuntu/.system-one-data/tool-risk
/home/ubuntu/.system-one-data/public/terminalbench
/home/ubuntu/.system-one-data/models/von-1.0
/home/ubuntu/.system-one-data/outputs/source-catalog.json
/home/ubuntu/.system-one-data/outputs/context-benign-catalog.json
/home/ubuntu/.system-one-data/outputs/s1-n1000
/home/ubuntu/.system-one-data/hf-stage
```

S1 corpus:

```text
cases: /home/ubuntu/.system-one-data/outputs/s1-n1000/cases.jsonl
manifest: /home/ubuntu/.system-one-data/outputs/s1-n1000/cases.manifest.json
SHA-256: 6d22d3d8fecec776ea254ef86e6e270e2fd7ffbe0cb01a295ac4d0e69ed0d6ca
families: 1,000
composition: A=40, B=410, C=150, D=400
```

Screen corpus:

```text
/home/ubuntu/.system-one-data/outputs/s1-n1000/screen-cases.jsonl
SHA-256: a16ad66ebac4804137daf608e648d07c9f59941e6b764d69de76cd6f690d34bd
rows: 200
composition: A=20, B=80, C=30, D=70
```

TerminalBench context diagnostic:

```text
normalized cases: /home/ubuntu/.system-one-data/outputs/terminalbench/cases.jsonl
partitioned development: /home/ubuntu/.system-one-data/outputs/terminalbench/partitioned/development.jsonl
with task-name intent: /home/ubuntu/.system-one-data/outputs/terminalbench/development-with-context.jsonl
selected 40: /home/ubuntu/.system-one-data/outputs/s1-n1000/terminalbench-context-cases.jsonl
```

## Dataset inventory

The catalog currently covers 18 corpora and about 413k rows. Before stricter truth grading was committed, aggregate counts were:

```text
A exact/outcome-backed: 363
B contextual trajectory: 3,695
C diagnostic: 2,976
D benign: 243,467
E out-of-scope/unknown: 162,679
```

Development availability from the same catalog was:

```text
A=46, B=2,479, C=1,507, D=38,717
```

A separate context/benign catalog includes TerminalBench and private coding traces:

```text
69,135 total
C=13,954
D=55,181
intent-present=1,416
```

Important: rerun `benchmark_inventory_system_one_sources.py` after the stricter truth-grade change before S2 selection. Do not assume old counts are final.

## Deterministic baseline

Completed and verified:

```text
/home/ubuntu/.system-one-data/outputs/s1-n1000/deterministic
```

The run is bound to the earlier clean remote commit `de1ccab6`; this is valid for S1 corpus evidence. Rebuild at current commit before any new deterministic stage because the harness requires binary VCS identity to equal worktree HEAD.

Build/run pattern:

```bash
cd /home/ubuntu/defenseclaw-system-one
commit=$(git rev-parse HEAD)
/usr/local/go/bin/go build -buildvcs=true -trimpath \
  -ldflags "-X main.buildCommit=$commit -X main.buildDirty=false" \
  -o bin/defenseclaw-benchmark ./benchmarks/cmd/defenseclaw-benchmark
```

## Completed Jev evidence

### Context screen

```text
predictions: s1-n1000/jev-context.jsonl
requests: 15,190
input tokens: 11,931,215
cost: $0.50111103
errors: 0
```

Selected exploratory context metrics:

```text
C0: F1 .87574, recall .84091, FPR .10000
C1: F1 .89017, recall .87500, FPR .11429
C7: F1 .83333, recall .73864, FPR .04286
CR: F1 .80519, recall .70455, FPR .05714
CS: F1 .80000, recall .70455, FPR .07143
CD: F1 .72973, recall .92045, FPR .75714 (reject)
```

C0 and C1 produced identical request hashes but 18/1,519 action flips (1.185%), which is direct repeatability evidence.

The context screen started before the hardening commit. Actual sample context sizes did not exceed 12,288 bytes, but treat it as exploratory and use hardened code for later stages.

### Instruction screen

```text
predictions: s1-n1000/jev-instructions.jsonl
requests: 12,152
actual input tokens: 8,830,672
cost: $0.37088822
errors: 0
```

Key metrics:

```text
C0/I3/Q0: F1 .89535, recall .87500, FPR .10000
C0/I1/Q0: F1 .69118, recall .53409, FPR .01429
C7/I0/Q0: F1 .82581, recall .72727, FPR .04286
C7/I3/Q0: F1 .78378, recall .65909, FPR .02857
```

Long/compact policy instructions reduce false positives but materially reduce recall. C0/I3 is quality-max; C7/I3 is lower-FPR.

## Active runs at handoff

### Hosted Jev question screen

```text
PID observed: 36354
run ID: s1-questions-jev
output: /home/ubuntu/.system-one-data/outputs/s1-n1000/jev-questions.jsonl
planned requests: 12,152
completed rows at capture: 5,464
contexts: C0,C7
instruction: I3
questions: Q0,Q1,Q2,Q3
```

Monitor:

```bash
wc -l /home/ubuntu/.system-one-data/outputs/s1-n1000/jev-questions.jsonl
ps -p 36354 -o pid,etime,stat,pcpu,pmem,args
```

### OpenJev question screen

```text
PID observed: 36460
run ID: s1-questions-openjev
output: /home/ubuntu/.system-one-data/outputs/s1-n1000/openjev-questions.jsonl
planned requests: 12,152
completed rows at capture: 1,108
GPU utilization observed: 100%
contexts: C0,C7
instruction: I3
questions: Q0,Q1,Q2,Q3
```

Monitor:

```bash
wc -l /home/ubuntu/.system-one-data/outputs/s1-n1000/openjev-questions.jsonl
ps -p 36460 -o pid,etime,stat,pcpu,pmem,args
ssh -i ~/.ssh/defenseclaw-system-one-gpu -o StrictHostKeyChecking=yes \
  ubuntu@43.202.158.42 \
  'nvidia-smi --query-gpu=memory.used,memory.total,utilization.gpu --format=csv,noheader'
```

Do not start duplicate runs. Both runners use ordered resumable prefixes and `.plan.json` identity files.

## OpenJev status

OpenJev exact model revision and documented stack are installed. Important deviations/controls:

- Hardware is L40S rather than reference H100; do not attribute H100 latency.
- FP8 load succeeded; model loading used 28.06 GiB and steady service uses about 40 GiB.
- `vllm==0.29.0`, `torch==2.13.0`, `transformers==5.17.0`, `openai==3.16.2`, `httpx==0.28.1`.
- FastAPI `0.136.3` and its flagged optional package were removed before serving; FastAPI is pinned to `0.136.1`, and `pip check` passed.
- Ubuntu `ninja-build` was installed because FlashInfer JIT required it.
- Shim SHA-256 reported: `81a22f1b1b8912a465059207ef9f60b7c6c16b4de6372305d867efbe38a1987a`.

Smoke results over 10 cases:

```text
80 requests, 0 errors
binary: 5 TP, 3 TN, 0 FP, 0 FN
three-way: contextual confirms were frequently promoted to block
```

This is only a smoke sample.

## Von status

Von `1.0.1` wheel was downloaded by exact SHA-256 and statically checked for obvious executable/deserialization patterns. It runs locally on CPU at `127.0.0.1:3100`.

```text
venv: /home/ubuntu/.von-venv
model: /home/ubuntu/.system-one-data/models/von-1.0
server PID observed: 37147
server log: /home/ubuntu/.system-one-von/server.log
```

The first 10-case runner smoke failed all 80 requests with `provider_or_parse_failure`; attempted calls were 160 due one retry. This is not a model-quality result. Diagnose wire/schema compatibility before further Von runs:

```bash
tail -n 100 /home/ubuntu/.system-one-von/server.log
python benchmarks/scripts/benchmark_run_system_one.py ... --endpoint http://127.0.0.1:3100/v1/systemone
```

Likely causes are endpoint/schema differences or server-side model loading errors. Do not include Von quality metrics until smoke has zero provider/parse errors.

## Private Hugging Face evidence repository

```text
repo: Vineethsain/defenseclaw-system-one-evaluations-v1
private: true
current revision: 9d319cb4e4cddfed6ee594d2e4afcd33fec0c875
```

Already uploaded:

```text
README.md
SHA256SUMS
governance/data-policy.json
protocol/v1/contexts-v1.json
protocol/v1/pilot-v1.json
protocol/v1/questions-v1.json
protocol/v1/source-catalog.json
protocol/v1/system-one-prediction-v1.schema.json
stages/s1-n1000/selected-ids.jsonl
stages/s1-n1000/selection.manifest.json
```

The source catalog currently on HF predates the final stricter truth-grade rerun. Replace it only by adding a new versioned path or a new immutable protocol revision; do not rewrite history silently.

Never upload source payloads unless their manifest explicitly permits private redistribution. Never upload credentials, headers, raw secrets, raw prompts/state, provider rationales, or incomplete live outputs.

## Immediate next steps

1. Wait for `jev-questions.jsonl` and `openjev-questions.jsonl` to reach 12,152 rows and their `.meta.json` files to show `complete: true`.
2. Score both question screens with `benchmark_score_system_one.py`; retain separate safety-max, balanced, and low-FPR candidates.
3. Debug Von smoke until the endpoint returns the expected typed schema or explicitly reject Von for protocol incompatibility.
4. Run Jev/OpenJev on the 40-case TerminalBench intent/context diagnostic to measure whether authenticated intent reduces benign false positives.
5. Rerun the hardened source inventory and create S1 final score/culling ledgers.
6. Run finalist configurations over the remaining S1 cases, then archive closed S1 artifacts/checksums to the private HF dataset.
7. Stop the GPU worker immediately after OpenJev S1 work.
8. Before S2, address the remaining scale issues below, rebuild deterministic at current commit, and produce a fresh cost projection.
9. Create disjoint S2 8k development + 2k validation selection from the catalog, excluding all S1 families.
10. Run S2 survivors and cull to at most 2-3 frozen finalists.
11. Build the S3 100k multi-lane corpus from untouched families; no tuning after S2.
12. Upload each closed stage with environment, configs, predictions, scorecards, culling decisions, costs, and checksums.

## Remaining implementation issues before 10k/100k

A read-only review identified these items. Critical context, delimiter, budget-attempt, bounded-future, resume-plan, duplicate/schema, truth-grade, and duplicate-quota issues were fixed in `81919bc99` / remote `63200b9b`.

Still address before scale-out:

- The runner still materializes all cases and all job states in memory before bounded submission. Refactor to a streaming/bounded job producer before S3 and preferably S2.
- `Budget.record_actual()` records actual tokens but does not currently abort when actual token cost exceeds the cap; enforce both reserved and actual ceilings.
- Resume binds case/config hashes and ordered identity but does not validate every prior row against the JSON Schema or recompute each request hash. Add validation before long-stage resume.
- Case scoring uses the most restrictive event to label a trajectory. Keep trajectory-level `any unsafe event` semantics explicit and add per-event activity/FPR metrics so a single event cannot hide event-level noise.
- Greedy overlapping quota allocation can depend on quota order. Implement specific-first or joint allocation before complex S2 quotas.
- `family_id()` may fall back to case ID; require dataset-specific stable family authority for all S2/S3 sources.
- Add atomic completion/closure manifests for stage scorecards and culling ledgers.
- Record Jev repeated-identical-request flip rate in the scorecard, not only ad hoc evidence.

## Cost controls

Observed hosted Jev spend so far before active question screen completion:

```text
context screen: $0.50111103
instruction screen: $0.37088822
```

The active Jev question screen has a `$1` hard configured cap. Check its completed metadata before starting another hosted run.

GPU On-Demand price is `$5.56762/hour` from launch time `2026-09-21T17:35:37Z`. Monitor runtime; stop immediately when OpenJev work is closed. The user explicitly approved On-Demand after Spot/H100/L40S capacity failures in `us-east-1`.

S2 and S3 require new measured cost projections and should not inherit S1 budget approval silently.

## Safety and governance

- Preserve exact deterministic decisions.
- Keep exact, contextual, benign-only, protected, and diagnostic truth lenses separate.
- Never tune on protected TS-Bench, validation, or sealed test rows.
- Keep every provider input/output and artifact revision pinned.
- Treat state/tool content as untrusted.
- Do not expose vLLM or shim ports publicly.
- Do not weaken repository security policies to satisfy dependencies.
- No X.509 certificate data was encountered; certificate sanity checks were therefore not triggered.
- Jev/HF/AWS credentials remain runtime-only and must never enter code, docs, logs, or HF artifacts.
- Do not terminate the GPU or delete its volume/security group without explicit user confirmation. Stopping the instance after active inference is expected and reversible.
