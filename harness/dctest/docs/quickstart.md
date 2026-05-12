# dctest quickstart

The minimum hands-on path through the harness, from a clean Mac/Linux shell.

## 0. Prereqs

- Python 3.10+ on PATH.
- `git`, `curl`, and `docker` (the latter is only needed for stories that boot the local observability stack).
- `defenseclaw` and `defenseclaw-gateway` installed and on PATH (`make install` from the DefenseClaw root).
- At least one AI agent CLI: `claude` (Anthropic Claude Code) and/or `codex` (OpenAI Codex).

## 1. Install dctest in editable mode

```bash
cd harness/dctest
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
dctest --version
```

## 2. Run doctor

```bash
dctest doctor
```

`doctor` prints a table of prerequisite checks. Anything reading "no" must be resolved before per-PR runs; missing optional things (Codex CLI, Docker) downgrade specific cells to `blocked` but do not prevent the run from starting.

## 3. Intake a worktree

```bash
dctest intake --worktree-path ../.. --slug pr-261-smoke
```

This writes `runs/pr-261-smoke/run.json` with the target HEAD SHA pinned. Every subsequent step refers to the run by its slug.

## 4. Plan and select a matrix slice

```bash
dctest matrix list --filter provider=anthropic-claude-sonnet --filter connector=codex
dctest matrix select \
  --filter provider=anthropic-claude-sonnet \
  --filter connector=codex \
  --output runs/pr-261-smoke/selection.yaml
```

The default expansion is `required-only`, sampling 3 (opa × pack) profile combinations. Pass `--full-profiles` for the full 3×3 grid, or `--include-optional` to test optional connectors.

## 5. Execute

```bash
# Live (the agent literally calls `claude -p` for each case classification)
dctest run pr-261-smoke --selection runs/pr-261-smoke/selection.yaml --backend claude

# Manual (you point an agent at staged/<stage>/prompt.txt yourself)
dctest run pr-261-smoke --selection runs/pr-261-smoke/selection.yaml --backend manual
# ... agent writes verdict.json files ...
dctest collect pr-261-smoke
```

## 6. Score and report

```bash
dctest score pr-261-smoke    # exit 0/1/2 for CI gating
dctest report pr-261-smoke   # writes runs/pr-261-smoke/report.md
```

`report.md` has top-level pass/fail counts, per-cell verdict tables, an explicit failures section, and a "needs human review" section.

## 7. Roll back lifecycle damage if anything went sideways

```bash
dctest snapshot list pr-261-smoke
dctest snapshot restore pr-261-smoke pre-init --dry-run
dctest snapshot restore pr-261-smoke pre-init
```

Snapshots are tarballs of `~/.defenseclaw`, `~/.openclaw`, `~/.codex/config.toml`, `~/.claude/settings.json`, etc. They are created automatically by lifecycle case YAMLs before destructive commands, and `dctest snapshot restore` refuses to write outside the user's `$HOME` or `/tmp`.

## What you should NOT do

- Edit case YAMLs to make a failing case pass; instead, file a defenseclaw bug.
- Run dctest in your "real" home directory. Use a dedicated test box / VM / container, especially for lifecycle and connector install cases.
- Commit `runs/`. It's in `.gitignore`.
