# Performance, size and footprint

Open this when: your change runs on the agent hook path, in the gateway request path, in the audit store, in telemetry export, in scanning, in the TUI refresh loop, or adds a background task, dependency or binary.

Hooks run on every agent tool call. Every feature must be switchable off, cost nothing when off, and add no work to the hot path. The repository has no wall-clock latency gate; guards are bounded constants, allocation and query counts, and off switches. You must measure and put numbers in the PR.

## Requirements

IDs live only in `reference/checklist.md`. These rows add detail and carry no IDs.

| Rule | Why | How to check | Evidence |
|---|---|---|---|
| Keep the hook to one local call: read stdin up to the cap, make one bounded HTTP call to the local gateway, exit. No disk scans, discovery, subprocesses or heavy init in the hook binaries. Expensive work belongs in the gateway or a background worker. | Latency is paid per tool call; the agent kills the hook at its timeout. | `go test ./internal/gateway/connector/hookexec/... ./cmd/defenseclaw-hook/...`; `make check-quiet-startup` | `cmd/defenseclaw-hook/main.go`, `internal/gateway/connector/hookexec/hookexec.go` |
| Derive a hook budget from the agent's registered timeout minus the response grace. Set the registered timeout and the hook budget together, per connector and event. Every retry or backoff must fit inside the shortest budget. | An over-long budget makes the agent kill the hook before it answers fail-open or fail-closed. | `go test ./internal/gateway/connector/hookexec/ -run 'Timeout\|ColdStart\|Deadline'` | `internal/gateway/connector/hookexec/hookexec.go` (`@sym:hookRequestTimeout`, `@sym:hookResponseGrace`), `internal/gateway/connector/claudecode.go` |
| Bound every hook and API input: hook stdin, API mutations and OTLP each have a byte cap (`@sym:defaultMaxBody`, `@sym:apiRequestBodyMaxBytes`, `@sym:otlpRequestBodyMaxBytes`). New endpoints go through the body-limit middleware or `MaxBytesReader`. | Unbounded bodies are a memory-exhaustion path on a multi-user gateway. | `go test ./internal/gateway/ -run 'BodyLimit\|Oversize'`; `grep -n MaxBytesReader internal/gateway` | `internal/gateway/api.go`, `internal/gateway/connector/hookexec/oversized_refusal.go` |
| Keep admission control on hook endpoints: per-caller rate, burst and in-flight limits and a global in-flight cap that answers 429 immediately, not a queue. A request waiting on a remote scanner or judge yields its run slot. Do not raise limits without a load measurement. | Under a burst, late answers are useless because clients already gave up; one user must not starve others. | `go test ./internal/gateway/ -run 'HookCaller\|RateLimit'` | `internal/gateway/hook_caller_limits.go`, `internal/gateway/api_ratelimit.go` |
| Never queue the LLM judge on the hook path. Keep the semaphore, skip the judge at capacity and fall back to the rules verdict, and keep the judge timeout below the shortest hook budget. The judge stays opt-in. | A queued judge call stalls the agent past its deadline. | `go test ./internal/gateway/ -run HookJudge` | `internal/gateway/inspect.go`, `internal/gateway/api.go` |
| Keep rule evaluation inside the compile-time and runtime cost model (rule count, static cost, expression and regex size, node and depth caps). Raise a constant only with a test and a cost justification. Rule regexes must be RE2-safe. | Rule packs are customer-extensible and run on every tool call. | `go test ./internal/guardrail/semantic/... ./internal/actionfacts/...` | `internal/guardrail/semantic/limits.go`, `internal/guardrail/semantic/cost.go`, `internal/actionfacts/limits.go` |
| Code that runs as root for a user (enterprise hook and scan workers) is a short-lived child with enforced limits: no core dumps, file-size and file-count rlimits, a data limit with a Go soft memory limit, request and response caps, a deadline, bounded parallelism, and a per-account breaker. | An unbounded root worker can exhaust host memory and take other services down. | `go test ./internal/cli/ -run 'EnterpriseHookWorker\|AIDiscoveryPass'` | `internal/cli/enterprise_hooks_worker_unix.go`, `internal/cli/enterprise_hooks_ai_discovery_unix.go` |
| Treat the audit SQLite store as a single-writer resource: WAL, one open connection, pragmas in the DSN, application-level BUSY retry, a separate connection for checkpoints. No long transactions or writes that bypass the store. | Hooks queue behind the writer; long writes cut hook throughput by a large factor. | `go test ./internal/audit/ -run 'SQLite\|Busy\|WAL'` | `internal/audit/store.go`, `internal/audit/sqlite_wal_guard.go` |
| Keep retention incremental and time-boxed: small delete batches, a schedule with a short follow-up while a backlog remains, and a run budget for correlation drain. Keep the short default retention in sync across schema, Go and Python. Measure writer hold time before changing a batch size. | Long retention grows the database without bound; large delete batches hold the writer and block hooks. | `go test ./internal/audit/ -run Retention`; `go test ./internal/audit/ -bench Retention -run '^$'` | `internal/audit/retention_v8.go`, `internal/audit/retention_benchmark_test.go`, `schemas/config/v8/defenseclaw-config.schema.json` |
| Every telemetry destination uses bounded, byte-aware queues and batches. A full queue drops and counts; it never blocks the hook or gateway. Disabled signals cost near zero. | An unbounded exporter queue leaks memory when a collector is slow. | `go test ./internal/observability/... -bench . -benchmem -run '^$'` | `internal/config/observability_v8_compile.go`, `internal/observability/runtime/benchmark_test.go` |
| Every optional feature ships with an off switch and starts no goroutine, watcher, timer or listener unless enabled. Prove it (see below). | Defaults run on laptops; enterprise multiplies background cost by users. | `go test ./internal/observability/runtime/ -bench Disabled -benchmem -run '^$'` | `internal/gateway/api.go` (nil when off), `internal/config/defaults.go` |
| Keep release binaries lean and reproducible: `CGO_ENABLED=0`, `-trimpath`, `-ldflags '-s -w'`. The Windows hook launcher stays at or below its size ceiling. Add no heavy dependency to the hook or launcher binaries. | A larger hook binary raises process-start cost on every tool call; CI fails above the ceiling. | `make lint` (repro-flags parity); `.github/workflows/windows-native.yml` size step | `scripts/build-release-assets.sh`, `cmd/defenseclaw-hook-launcher/main.go` |
| Do not hand-edit generated bulk and do not commit datasets. Datasets are downloaded into an ignored directory and pinned in `benchmarks/datasets.lock.json`. | Generated catalogs drift; corpora bloat clones. | `make check`; `git status` after generators is clean | `benchmarks/README.md`, `benchmarks/datasets.lock.json` |
| Keep hook dial timeout short and never follow redirects. | A hijacked address must not stall the agent or leak the token. | `go test ./internal/gateway/connector/hookexec/` | `internal/gateway/connector/hookexec/hookexec.go` |
| Keep static scanning bounded: file count and size caps, skip dirs and binary extensions, no link following. No whole-tree reads on the hook path or in the install watcher. | An unbounded skill directory stalls the gateway. | `go test ./internal/guardrail/ -run Artifact` | `internal/guardrail/artifact_scan.go` |
| Use a Windows job object with kill-on-close for child process trees. | Orphaned children leak CPU and memory on shared hosts. | `go test ./internal/processutil/...` on Windows | `internal/processutil/command_windows.go` |
| Do not add per-profile work that scales with profile count on every load. Copy once, decode once, and keep `AllocsPerRun` assertions. | Large profile counts made starts and reloads slow. | `go test ./internal/config/ -run Profiles` | `internal/config/guardrail_profiles_test.go` |
| Keep TUI refresh generation-aware: one query per changed database generation, none for an unchanged one, read-only open, no timer-driven full rescans. Measure by query count. | Timer-driven rescans of a large database burn CPU while the TUI is idle. | `python scripts/benchmark_tui_refresh.py --rows 1000`; `pytest cli/tests/tui -q` | `scripts/benchmark_tui_refresh.py`, `cli/tests/tui/test_refresh_baseline.py` |
| Keep start-up silent and cheap: version probes exit 0 with empty stderr and do no config load, network call or disk scan before argument handling. | Installers and doctor run them many times. | `make check-quiet-startup` | `Makefile`, `cli/tests/test_doctor_startup_preflight.py` |
| Guard performance with allocation or query counts and Go benchmarks, not wall-clock thresholds. Name the defect that motivated the guard in the test. | Timing thresholds are flaky on shared CI. | `go test -bench . -benchmem -run '^$' ./internal/observability/... ./internal/audit/...` | `scripts/benchmark_tui_refresh.py` |
| Balance a new heavy Go package through the shard script, not by adding it to one shard. | One oversized shard is the critical path. | `python3 scripts/go_test_shards.py --help` | `scripts/go_test_shards.py`, `.github/workflows/ci.yml` |
| Treat `benchmarks/` as an accuracy and conformance harness. Do not quote its output as latency. | It measures detection quality. | steps in `benchmarks/README.md` | `benchmarks/README.md` |
| Put before and after numbers in the PR body. | No CI gate catches a latency regression. | read the PR body | `.github/pull_request_template.md` |
| Keep the docs-site build lean and deterministic. | It builds on every docs change and has no size budget. | `cd docs-site && npm run build` | `.github/workflows/docs-site.yml` |

## Budgets (read the constants in code; do not copy numbers into new docs)

| Area | Where the constant lives |
|---|---|
| Hook stdin cap, hook budget, dial timeout, retries | `internal/gateway/connector/hookexec/hookexec.go` |
| Per-caller and global in-flight limits | `internal/gateway/hook_caller_limits.go` |
| Judge concurrency and timeout | `internal/gateway/inspect.go` |
| CEL and regex limits | `internal/guardrail/semantic/limits.go` |
| Worker limits and breaker | `internal/cli/enterprise_hooks_worker_unix.go` |
| Retention and batch size | `internal/audit/retention_v8.go`, `internal/config/observability_v8_types.go` |
| Telemetry queue and batch defaults and ceilings | `internal/config/observability_v8_compile.go` |
| Config source size limits | `internal/config/observability_v8_types.go` |
| CI shards and timeouts | `.github/workflows/ci.yml` |

## Proving a feature costs nothing when off

1. Default the switch to off in the schema and both loaders.
2. Construct the component only when enabled (the field stays nil, no goroutine, no listener, no timer).
3. Add a test that builds the app with the switch off and asserts the field is nil, no goroutine started, no file opened.
4. Add a `Disabled` benchmark with `-benchmem` showing zero allocations per call on the hot path.
5. Record the hook latency before and after, with the feature off, in the PR.

## Measurement recipes

- Hook latency: time `defenseclaw-hook` end to end against a running gateway, 100 calls, report median and p95; repeat with concurrent callers on a multi-core host.
- Audit store: retention benchmark plus a synthetic database (`scripts/benchmark_tui_refresh.py` has the builder).
- Observability: `go test -bench . -benchmem -run '^$' ./internal/observability/...`.
- Size: `ls -l` the built binaries before and after; compare wheel size with `du`.
- Enterprise scale: many users and sessions on one host; watch worker memory, writer hold time and 429 rate. The load recipes are not in the repository; record your method in the PR.

## Where it lives

`cmd/defenseclaw-hook/`, `cmd/defenseclaw-hook-launcher/`, `internal/gateway/`, `internal/audit/`, `internal/observability/`, `internal/guardrail/semantic/`, `internal/cli/enterprise_hooks_*`, `scripts/benchmark_tui_refresh.py`.

## How to verify

Run the tests and benchmarks in the table for the package you touched, then attach numbers to the PR.

## Common mistakes

- Doing config loads or file scans in a hook binary's init.
- Adding a retry that overruns the shortest agent timeout.
- Setting only the hook budget and not the registered agent timeout.
- Queueing instead of refusing under load.
- Enlarging a retention batch without measuring writer hold time.
- Copying the config once per profile.
- Trusting stale comments that still describe shell hook scripts; read `hookexec.go`.
