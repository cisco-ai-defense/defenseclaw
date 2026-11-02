# Performance harness

`dcperf.py` measures one per-user DefenseClaw install on the host it runs on.
It needs Python 3.11+ and nothing else (strace, when present on Linux, adds
the processes-per-hook count; on macOS an `eslogger` log adds it, below).
Started by an older `python3` (macOS ships 3.9, RHEL 9 ships 3.9), it runs
itself again under the DefenseClaw venv Python (3.12) of the install it
measures. It never reads or prints a credential.

| Metric (JSON key) | What it measures |
|---|---|
| `hook.<claudecode,codex>.idle` | p50/p95/max of 100 sequential benign PreToolUse calls through the hook command the connector registered (`~/.claude/settings.json`, `~/.codex/config.toml`), run with `/bin/sh -c` as the agent runs it |
| `hook.<connector>.burst` | the same, 128 calls 32 at a time |
| `hook.<connector>.*.not_allowed` | benign calls that were denied or failed (must be 0) |
| `hook_execs.claudecode` | execs and processes per hook call, by program (Linux `strace -f`, also by parent; macOS an `eslogger exec fork` log) |
| `hook_execs.claudecode.gateway_execs_per_call` | macOS: execs the gateway and its children ran while the traced calls ran, per call (10 calls a second apart); left out, with `gateway_events_dropped` set, when Endpoint Security dropped any exec or fork event in that span |
| `gateway_restart.to_api_ready` | `defenseclaw-gateway restart` until `/health` answers from the new process |
| `cli.status`, `cli.doctor`, `cli.setup_claudecode` | wall time of `defenseclaw status`, `doctor`, `setup claude-code --yes --no-restart` |
| `cli.skill_scan` | `defenseclaw skill scan --path fixtures/benign-skill --no-use-llm --json` |
| `gateway_rss_kb.after_idle` | gateway RSS after `idle_s` seconds without traffic (`--rss-idle`, 300 by default) |
| `gateway_rss_kb.anon_kb`, `file_kb`, `audit_db_kb` | the heap and file-backed parts of that RSS (Linux RssAnon/RssFile; macOS `vmmap -summary`: physical footprint and resident mapped files), and the audit.db size. Until rel-1-0-6 GAP-0327 the gateway mapped audit.db (SQLite mmap, 256 MiB) and the pages it read stayed resident, so the file-backed part, and the total, grew with the store |

Run it against your own install, or against a throwaway one:

```bash
# your install (HOME), about 7 minutes
python3 scripts/perf/dcperf.py run --out perf.json --budgets scripts/perf/budgets.json --column linux-per-user

# a throwaway install of release assets (scripts/build-release-assets.sh output)
python3 scripts/perf/dcperf.py provision --assets ASSETS_DIR --home /tmp/perf-home
python3 scripts/perf/dcperf.py run --home /tmp/perf-home --out perf.json

# macOS: count execs per hook with Endpoint Security. Only root may run
# eslogger; start it in a root shell of its own (not as a parent of the
# harness), point the harness at its log, and stop it after the run with
# SIGTERM: a background job of sh ignores SIGINT, and an eslogger left
# running keeps a client on every exec and fork of the Mac. The log grows
# about 20 MB a minute on a busy Mac.
# Endpoint Security makes every exec on the Mac slower while eslogger runs (a
# hook call runs 13), so trace the execs in a pass of their own and measure
# the rest without it, then check the two passes together.
sudo sh -c 'eslogger exec fork > /var/tmp/dcperf-es.jsonl 2>/dev/null & echo $! > /var/tmp/dcperf-es.pid'
python3 scripts/perf/dcperf.py run --only execs --eslogger-log /var/tmp/dcperf-es.jsonl --out perf-execs.json
sudo kill -TERM "$(cat /var/tmp/dcperf-es.pid)"   # flushes the log
python3 scripts/perf/dcperf.py eslogger-parse perf-execs.json --eslogger-pid "$(cat /var/tmp/dcperf-es.pid)"
sudo rm -f /var/tmp/dcperf-es.jsonl /var/tmp/dcperf-es.pid
python3 scripts/perf/dcperf.py run --only hook,cli,restart,rss --out perf-rest.json
python3 scripts/perf/dcperf.py compare perf-execs.json perf-rest.json --budgets scripts/perf/budgets.json --column macos-per-user

# check a saved result (or several passes, merged) against the budgets
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
The budgets were measured on the install `provision` makes (Claude Code and
Codex, observe mode). Measure that shape: every other connector enrolled
in config.yaml adds gateway work, and `setup` runs its agent CLI again
after that CLI changed, so a result from another install is not comparable.
