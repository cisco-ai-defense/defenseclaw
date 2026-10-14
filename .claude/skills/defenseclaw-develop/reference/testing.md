# Testing: what to run for what you touched

Open this when: you decide which tests and gates to run, add a test, regenerate a golden, change CI classification, or touch installers, Windows or enterprise code.

The authoritative checklist is `docs/TESTING.md` ("Before a PR") and `CONTRIBUTING.md`. This file adds the routing and the rules reviewers apply.

## Requirements

IDs live only in `reference/checklist.md`. These rows add detail and carry no IDs.

| Rule | Why | How to check | Evidence |
|---|---|---|---|
| Before a PR run `make lint`, `make test`, `make ts-test`, `make rego-test`, `make check`, scoped to the areas touched. | They mirror the required CI jobs. | `make lint && make test && make check` | `docs/TESTING.md`, `CONTRIBUTING.md`, `Makefile` |
| `make test` is only the Python suite plus the Go gateway and `test/` packages. `ts-test`, `rego-test`, `check`, `lint`, `tui-test`, `connector-matrix-test` and `telemetry-check` are separate. | Green `make test` with a red `make check` is the usual local-green, CI-red path. | read the `Makefile` `.PHONY` line | `Makefile` |
| A behavior change ships with a test that fails without it. | Reviewers reject unpinned fixes. | revert the production change locally; the test must fail | `CONTRIBUTING.md` |
| New Go tests are race-clean and never order events with sleeps. | CI runs `-race` on every shard. | `go test -race -gcflags=modernc.org/...=-d=checkptr=0 -count=1 ./internal/<pkg>` | `Makefile` (`GO_RACE_FLAGS`) |
| Keep `scripts/ci_changes.py` and `cli/tests/test_ci_changes.py` in sync with any new test, workflow, doc a test reads, or script. Gated jobs use `!= false` so a failed classifier runs everything. | A wrong rule silently skips a required gate; skipped aggregates pass. | `pytest cli/tests/test_ci_changes.py cli/tests/test_ci_workflow_efficiency.py` | `scripts/ci_changes.py`, `.github/workflows/ci.yml` |
| Audit action, error code and schema changes pass `make check-v7`. Use typed constants, not raw action literals. | Go, Python and `schemas/` drift fails CI. | `make check-v7` | `scripts/check_audit_actions.py`, `scripts/check_error_codes.py`, `scripts/check_schemas.py` |
| Telemetry registry changes use `make telemetry-generate` then `make telemetry-check`. Registry, compiler and schema changes also trigger the exhaustive telemetry workflow. | Stale generated outputs fail; exhaustive suites run only for sensitive PRs and nightly. | `make telemetry-check` | `.github/workflows/telemetry-registry.yml`, `scripts/generate_telemetry_registry.py` |
| Observability changes keep `make check-observability-v8-hard-cut` and `make check-grafana-dashboards` green; keep the packaged dashboard copy (built by the Makefile `_bundle-data` step) in sync. | Retired runtime APIs must not return; dashboards must not query metrics that do not exist. | `make check-observability-v8-hard-cut check-grafana-dashboards` | `scripts/check_observability_v8_hard_cut.py`, `scripts/check_grafana_dashboards.py` |
| Provider or endpoint shape changes update `test/testdata/llm-endpoints.json` and pass `make check-provider-coverage`. | Go and TS interceptors drifting is a silent bypass. | `make check-provider-coverage check-llm-catalog` | `test/testdata/llm-endpoints.json`, `bundles/llm/model_catalog.json` |
| Regenerate a Go golden only with `DEFENSECLAW_UPDATE_GOLDEN=1` for the one affected test, then review the diff. Never hand-edit goldens or digest-pinned fixtures. | Goldens encode security-relevant contracts. | `DEFENSECLAW_UPDATE_GOLDEN=1 go test ./policies/kernel -run <Test> -count=1; git diff` | `policies/kernel/kernel_test.go`, `internal/openshell/profiles/profiles_test.go`, `scripts/live-connector-e2e/golden` |
| Python tests rely on the autouse isolation fixtures (isolated home, subprocess ban, stubbed discovery). Do not touch the real home, network, gateway or host discovery. Use the `allow_subprocess` marker only for executor integration tests. | Tests must not change a developer or CI profile. | `pytest cli/tests/<module> -q` | `cli/tests/conftest.py`, `pyproject.toml` (markers) |
| Connector changes run `make connector-matrix-test` and update golden stdin payloads when an upstream hook contract changes. Use the add-connector skill. | The contract matrix runs on every PR. | `make connector-matrix-test` | `Makefile`, `test/e2e/connectormatrix.go`, `scripts/live-connector-e2e/golden` |
| Windows-affecting code is validated natively: `windows-native.yml` Go shards, Python shards and PowerShell harnesses. Use `_windows_test.go` / `_other_test.go` pairs and run `GOOS=windows go vet ./...` locally. | ACL, service, installer and path behavior differ. | `GOOS=windows go vet ./...`; dispatch `windows-native.yml` | `.github/workflows/windows-native.yml`, `scripts/windows-native-ci.ps1`, `packaging/windows/tests` |
| Installer, migration, upgrade, rollback, gateway startup and packaging changes run the install-lifecycle scenarios (`fresh`, `upgrade-previous`, `upgrade-0.8.10`, `handoff`, `drills`) with real built assets, and the enterprise install jobs on disposable hosts only. Keep the 0.8.x to 1.x upgrade passing. | These are the only proof of upgrade, rollback and interrupted-swap behavior. | `scripts/build-release-assets.sh <ver> <dir>` then `scripts/test-install-lifecycle.sh --assets <dir> --previous-assets <dir> --lanes "fresh upgrade-previous upgrade-0.8.10 handoff drills"` | `scripts/test-install-lifecycle.sh`, `scripts/test-install-lifecycle.ps1`, `docs/TESTING.md` |
| Do not treat a green contract or synthetic job as certification for a connector or platform claim. Support claims need interactive verification on each OS claimed; if you cannot run an OS you claim, say so and a maintainer will. | Synthetic jobs do not run real agents, real identity or real MDM. | manual run recorded in the PR Test Plan | `.github/workflows/connector-live-e2e.yml` |
| Security, installer, upgrade and managed-lifecycle changes also get manual verification on a machine or VM you control (a disposable one for installers and managed mode), with exact commands and observed results in the PR Test Plan. | Hosted runners lack real agents, directory identity and signed packaging. | read the Test Plan section | `.github/pull_request_template.md`, `docs/ENTERPRISE-TEST-PLAN.md` |
| Iterate with the cheapest focused run: `make test-file FILE=<module>`, `go test ./internal/<pkg> -run <Name> -count=1`, `vitest run <file>` in `extensions/defenseclaw`, `opa test policies/rego/`. | Full suites per edit are slow. | n/a | `docs/TESTING.md` (Focused Tests) |
| Run the big gateway package through the shard runner (`make gateway-test`) or with `-timeout 30m`. | The default 10 minute deadline is too short. | `python3 scripts/go_test_shards.py --help` | `scripts/go_test_shards.py`, `Makefile` |
| TUI tests: unit-test models and services first; at most two Pilot tests per new screen at 80x24 on `fixtures.snapshot_app`; no sleeps, copy assertions, private attributes or golden SVGs. Load the defenseclaw-tui skill. | Pilot tests are slow and flaky. | `make tui-test` | `cli/tests/tui/test_smoke.py`, `.claude/skills/defenseclaw-tui/SKILL.md` |
| Detection changes run `make security-suite-test`; judge changes also run the opt-in live scoring `make security-suite-eval` (needs `DEFENSECLAW_LLM_KEY`, never in CI). | Rule and judge regressions are invisible to unit tests. | `make security-suite-test` | `docs/SECURITY-TEST-SUITE.md`, `internal/gateway/testdata/security_suite` |
| Run `make check-quiet-startup` after dependency or Go version bumps. | Startup warnings reach MDM output and hook error text. | `make check-quiet-startup` | `Makefile` |
| Docs changes pass the docs-site steps locally and keep generated policy assets committed. | CI fails on uncommitted assets and broken links. | `cd docs-site && npm ci && npm run lint && npm run validate-links && npm run build` | `.github/workflows/docs-site.yml` |
| Maintainers: on a busy branch, dispatch `gh workflow run ci.yml --ref <branch>` (and `windows-native.yml`). Contributors working from a fork: ask a maintainer to re-run. | Each push cancels running CI; a cancelled run is not a pass. | n/a | `docs/TESTING.md` (CI Workflows) |

## What to run per area

| You touched | Run |
|---|---|
| Go package | `go test -race ./internal/<pkg>`, `make go-lint` |
| Python CLI | `make test-file FILE=<module>`, `make lint` |
| Config or schema | `reference/config.md` checks, `make check` |
| Rego or rule packs | `make rego-test`, `go test ./internal/policy ./internal/guardrail` |
| TUI | `make tui-test` |
| Connector | `make connector-matrix-test`, add-connector skill |
| Telemetry | `make telemetry-check` |
| Docs-site | docs-site npm steps, `python scripts/check_docs_cli_commands.py` |
| Installer, upgrade, packaging | install-lifecycle scenarios, enterprise jobs |
| Windows code | `GOOS=windows go vet ./...`, `windows-native.yml` |

## OS matrix

Linux, macOS and Windows each have their own required job. Do not run enterprise install scenarios on a developer machine: they install system services as root. macOS packaging needs `VERSION=<x>` explicitly.

## Goldens, differential and corpus tests

- Goldens regenerate per the golden rule in `reference/checklist.md`. The kernel, kernelpolicy, OpenShell profile and per-connector layout goldens are security contracts.
- Differential: Rego and its Go fallback must agree (`TestAdmissionRegoAndFallbackAgree`); Go and TS provider coverage share one corpus; Python and Go rule-pack loaders share fixtures.
- Corpus: detection corpora live under `internal/gateway/testdata/security_suite` and `benchmarks/`. Measure recall on attack data and false positives on benign data separately.

## Flaky-test policy

The repository has no quarantine or retry mechanism. Fix the cause. Avoid fixed ports (allocate free ones), the real home (use a throwaway), sleeps (await events), shared persistent host state, and timing thresholds. Count-based assertions beat wall-clock ones. Never skip a failing test to merge.

## How to verify

Run the table row for each area, then `make lint test ts-test rego-test check`, and quote the commands and results in the PR Test Plan.

## Common mistakes

- Running only `make test`.
- Running `go test ./internal/gateway` bare and reading a timeout as a failure of the change.
- Regenerating a golden to turn a failure green.
- Adding a test file and not updating `ci_changes.py` rules where needed.
- Treating a cancelled CI run as passing.
- Staging stray scratch files from the repository root; stage explicit paths.
