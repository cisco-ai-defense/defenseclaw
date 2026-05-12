# Troubleshooting

Symptoms and fixes for the common failure modes.

## `dctest doctor` says "claude CLI on PATH: no"

Install Claude Code (https://docs.anthropic.com/claude/claude-code) and make sure `claude --version` works in the same shell where you run `dctest`. If you have a non-standard path, set `DCTEST_CLAUDE_BIN=/full/path/to/claude` in `.env`.

## Cells stuck in `needs-human` after a run

The agent backend was unable to write `verdict.json`. Reasons:

- The agent ran out of tokens / context. Reduce the matrix slice (`--filter`), or split the run into multiple smaller `dctest run --cases` invocations.
- The backend timed out. Bump `DCTEST_AGENT_TIMEOUT_S` (default 900s).
- The agent's last message contains an explicit "I cannot decide because ..." — this is intended and signals a real ambiguity. Read `runs/<id>/cells/<cell>/cases/<case>/stdout.txt` yourself, write a verdict manually (`echo '{"verdict":"pass","reasoning":"manual: ..."}' > .../verdict.json`), and re-run `dctest collect`.

## A lifecycle case wiped my $HOME/.defenseclaw and the run aborted

```bash
dctest snapshot list <run-id>
dctest snapshot restore <run-id> pre-<label>
```

If the snapshot was never created (the case crashed *before* writing it), look in `runs/<id>/snapshots/` for the most recent `pre-*.tgz`. If there's none, `defenseclaw init --no-interactive` will recreate a fresh-but-empty `~/.defenseclaw`.

## Webhook fixture says "port 9777 already in use"

```bash
lsof -ti tcp:9777 | xargs kill
```

The fixture binds to `127.0.0.1:9777`; it's safe to kill any process holding the port.

## Local observability stack: Grafana login fails

You forgot to edit `fixtures/observability/grafana-admin-password.txt` after copying it from a clean checkout. Edit the file, `docker compose down && docker compose up -d`, and DO NOT commit your edited password.

## `pytest harness/dctest/tests` shows DeprecationWarning for `datetime.utcnow()`

dctest itself uses a centralized `dctest.utc_now` helper, but third-party libraries (e.g. older pydantic versions) may still trigger this warning. It's safe to ignore. Use `pytest -W ignore::DeprecationWarning` if you want a clean log.

## `dctest matrix list` produces 0 cells

Your filters are too aggressive. Drop one filter at a time until cells appear. Use `--include-optional` to verify whether the connector you're filtering on is in the `optional` tier (default is required-only).

## My PR introduced a new CLI subcommand — what now?

1. Add a `cases/cli/<group>.yaml` entry with `surface: python-cli` (or `go-cli`), the exact command, and clear `expected_substrings` / `must_not_contain` rules.
2. Append a row to `COVERAGE.md` under the right section.
3. Run `harness/dctest/.venv/bin/python -m pytest harness/dctest/tests/test_case_loader.py -q` to make sure the new case loads.
4. Run `dctest run <id> --cases <new-case-id>` against your worktree to verify the case actually executes.

## My PR added a new connector

1. Append it to `matrix/connectors.yaml` with `tier: required` (if it's first-party) or `tier: optional`.
2. Add a `cases/connectors/<name>.yaml` modeled on `connectors/codex.yaml`.
3. Add a verify-hint list to `services/connector_setup.py` so `connector plan` emits useful checks.
4. Update `COVERAGE.md`.

## My PR added a new policy profile

Append to `matrix/profiles.yaml` under `opa:` or `pack:`. Existing cases will pick up the new value automatically on the next `expand_matrix` call.
