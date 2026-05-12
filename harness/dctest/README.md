# dctest — DefenseClaw manual testing harness

A reproducible, AI-agent-driven harness for exercising every advertised DefenseClaw feature across the full provider × role × connector × scan-type × policy-profile × fail-mode matrix.

Models the [Avarice security harness](../../.avarice/src/avarice) architecture:

- subprocess-invoked agent backends (`claude`, `codex`, `manual`),
- a render → execute → collect pipeline with filesystem-backed state,
- resumable runs under `runs/<run-id>/`,
- programmatic markdown reports.

The harness **orchestrates and captures evidence**. A real AI agent (Claude Code or Codex) **decides pass/fail** by writing a `verdict.json` for every executed case.

## Quickstart

```bash
# 1. Install the harness in editable mode (Python 3.10+).
python3.13 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 2. Check prerequisites for the default matrix.
dctest doctor

# 3. Create a run from the worktree under test.
dctest intake --worktree-path .. --slug pr-261-2026-05-10

# 4. Pick a matrix subset and serialize it.
dctest matrix select --filter provider=anthropic-claude-sonnet --filter connector=codex \
  --output sel-codex-sonnet.yaml

# 5. Execute the run (live; backend=claude).
dctest run pr-261-2026-05-10 --selection sel-codex-sonnet.yaml --backend claude

# 6. Aggregate and report.
dctest score pr-261-2026-05-10
dctest report pr-261-2026-05-10
```

For manual operation (you driving the agent by hand):

```bash
dctest run pr-261-2026-05-10 --selection sel-codex-sonnet.yaml --backend manual
# now point Claude Code / Codex at staged/<stage>/prompt.txt
dctest collect pr-261-2026-05-10
```

## Layout

```
harness/dctest/
  pyproject.toml
  README.md
  src/dctest/
    cli.py                     # the `dctest` entrypoint
    config.py                  # DCTEST_*-prefixed Settings
    models/                    # Pydantic domain types
    services/                  # run_store, intake, snapshot, matrix, executor, stage_runner, case_runner, doctor, score, report
    cases/                     # shipped YAML test cases (cli, lifecycle, skills, connectors, gateway-api, stories, errors)
    matrix/                    # YAML axes (providers, roles, connectors, profiles, fail_modes, scan_types)
    fixtures/                  # skill manifests, MCP configs, code samples, policies, webhook target stub, observability stack
    prompt_assets/prompts/     # preamble + per-stage agent prompts
  tests/                       # the harness's own pytest suite
  runs/                        # per-run artifacts (gitignored)
```

## What "manual testing" means here

dctest does NOT auto-grade test cases. It:

1. Plans the matrix and writes one cell.json per (connector, provider, role, profile, fail-mode, scan-type) combo.
2. For every case, runs the command under test and captures stdout/stderr/exit code/timing.
3. Invokes the configured AI agent backend with the `classify_evidence.md` stage prompt and asks it to write `verdict.json`.
4. Aggregates verdicts into `SUMMARY.json` and assembles `report.md`.

If you want strict "machine-truth" assertions, write them as `expected_substrings` / `must_not_contain` in the case YAML — the agent will treat those as required preconditions for `pass`.

## Adding a case

Cases live under `src/dctest/cases/<feature>/*.yaml`. Minimum shape:

```yaml
cases:
  - id: cli-py.example.something
    title: short human description
    surface: python-cli   # python-cli|go-cli|tui|connector|gateway-api|story|lifecycle|error
    feature: example.something
    command: defenseclaw example something --json
    expected_exit_code: 0
    expected_substrings: ["ok"]
    must_not_contain: ["Traceback"]
```

Run `pytest harness/dctest/tests/test_case_loader.py -q` after editing to make sure ids stay unique and every case declares at least one expectation.

## Safety

- Lifecycle cases that mutate `$HOME` always snapshot first; `dctest snapshot restore <run-id> <label>` will roll back to a known state.
- The executor scrubs known token patterns (`sk-...`, `AKIA...`, JWTs, private-key blocks) from captured stdout/stderr before writing them to disk.
- Webhook fixture binds to `127.0.0.1:9777` only and caps body size at 1 MiB.
- Docker fixtures drop all capabilities, run with `no-new-privileges`, and never mount the Docker daemon socket.

See [`docs/`](docs/) for matrix recipes, the per-PR workflow, and troubleshooting.
