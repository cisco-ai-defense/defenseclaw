# Performance harness

`dcperf.py` measures one per-user DefenseClaw install on the host it runs on.
It needs Python 3.11+ and nothing else (strace, when present on Linux, adds
the processes-per-hook count). It never reads or prints a credential.

| Metric (JSON key) | What it measures |
|---|---|
| `hook.<claudecode,codex>.idle` | p50/p95/max of 100 sequential benign PreToolUse calls through the hook command the connector registered (`~/.claude/settings.json`, `~/.codex/config.toml`), run with `/bin/sh -c` as the agent runs it |
| `hook.<connector>.burst` | the same, 128 calls 32 at a time |
| `hook.<connector>.*.not_allowed` | benign calls that were denied or failed (must be 0) |
| `hook_execs.claudecode` | execs and processes per hook call (`strace -f`), by program and by parent |
| `gateway_restart.to_api_ready` | `defenseclaw-gateway restart` until `/health` answers from the new process |
| `cli.status`, `cli.doctor`, `cli.setup_claudecode` | wall time of `defenseclaw status`, `doctor`, `setup claude-code --yes --no-restart` |
| `cli.skill_scan` | `defenseclaw skill scan --path fixtures/benign-skill --no-use-llm --json` |
| `gateway_rss_kb.after_idle` | gateway RSS after `idle_s` seconds without traffic (`--rss-idle`, 300 by default) |
| `gateway_rss_kb.anon_kb`, `file_kb`, `audit_db_kb` | the heap and file-backed parts of that RSS (Linux), and the audit.db size: the startup quick_check reads audit.db through SQLite's mmap (up to 256 MiB), so the file-backed part, and the total, grow with the store while the heap stays flat |

Run it against your own install, or against a throwaway one:

```bash
# your install (HOME), about 7 minutes
python3 scripts/perf/dcperf.py run --out perf.json --budgets scripts/perf/budgets.json --column linux-per-user

# a throwaway install of release assets (scripts/build-release-assets.sh output)
python3 scripts/perf/dcperf.py provision --assets ASSETS_DIR --home /tmp/perf-home
python3 scripts/perf/dcperf.py run --home /tmp/perf-home --out perf.json

# check a saved result against the budgets
python3 scripts/perf/dcperf.py compare perf.json --budgets scripts/perf/budgets.json --column linux-per-user
```

`run` prints the JSON (or writes `--out`) and a one-line summary. With
`--budgets`, it exits 1 when a gated metric is more than the tolerance (20%)
over its budget, or was not measured. CI runs it on every pull
request that builds the install assets (job `perf-budget` in
`.github/workflows/ci.yml`).

`budgets.json` holds one column per OS and mode. Entries with a number are
gated, entries with `"gate": false` are shown but not gated, and `"TODO"`
entries have no baseline yet. Each entry names the measurement it came from.
