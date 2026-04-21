# CLI UX Overhaul — First-Run Quickstart, Credential Registry, Lifecycle Commands

**Status:** Accepted, shipping in the `feat/cli-ux-quickstart` stack
**Author:** DefenseClaw platform team
**Target base:** `feat/tui-help-text-and-concurrency-hardening`
**Related work:** P3-#21 (Overview Doctor cache), TUI ↔ CLI parity gate,
`cli(doctor): race-safe doctor_cache.json writes`

## Problem

A fresh clone of DefenseClaw needed roughly a dozen separate steps to
reach a functional guardrail:

1. Create a venv, `pip install .`
2. Run `defenseclaw init`
3. Run `defenseclaw setup <subcommand>` for each scanner/integration
4. Hand-edit `~/.defenseclaw/.env` to set API keys (no way to know
   which were required — `doctor` only covered a curated subset)
5. Run `defenseclaw setup guardrail` to patch `openclaw.json`
6. Build the Go gateway, manually copy to `~/.local/bin`
7. Manually prepend `~/.local/bin` to the shell rc file
8. Run `defenseclaw-gateway start`
9. Re-run `defenseclaw doctor` and interpret the output

Each step had its own prompt UX. Some defaulted to "interactive",
others to "non-interactive". CI jobs, containers, and unattended
installers all had to re-implement the orchestration themselves.

The lack of a first-class lifecycle story also meant uninstall,
reset, and self-check-with-auto-repair were left as manual
`rm -rf` instructions in the README.

## Goals

1. A single command, `make all`, takes a fresh clone to a working
   guardrail with one PATH prompt. All subsequent invocations are
   idempotent.
2. API-key handling is registry-driven: new features declare their
   credential needs in one place and `doctor`, `keys`, `quickstart`,
   and the TUI all pick them up automatically.
3. Destructive operations (`uninstall`, `reset`) are explicit,
   auditable, and refuse to touch paths that don't look like
   DefenseClaw-owned directories.
4. Configuration drift is self-healing for common cases via
   `doctor --fix` — no state mutation the user didn't authorize.
5. Version drift between CLI, gateway, and OpenClaw plugin is
   visible at a glance via `defenseclaw version`.

## Non-goals

- Replacing the existing OpenClaw installer or mutating OpenClaw
  config beyond the plugin registration + guardrail traffic route.
- Packaging DefenseClaw as a distro-native artifact (`brew`,
  `apt`, `rpm`). That remains `goreleaser` territory.
- Building a TUI-native key-entry wizard. The CLI
  `defenseclaw keys fill-missing` flow remains canonical; the TUI
  surfaces missing keys but shells out / hands off.

## Architecture

### The credential registry

`cli/defenseclaw/credentials.py` introduces `CredentialSpec` and the
module-level `CREDENTIALS` list. Each entry declares:

- `env_name` — the environment-variable name we look up
- `feature` — human-readable grouping for the UX
- `description` — one-line explainer
- `required(cfg)` — predicate that takes the loaded `Config` and
  returns `REQUIRED`, `OPTIONAL`, or `NOT_USED` based on which
  features the operator has enabled
- `resolve(cfg)` — returns `(value, source)` so the caller can
  distinguish "unset", "set via .env", and "set via OS env"

`classify(cfg)` walks every spec and produces the unified list the
other subsystems consume:

- `defenseclaw keys check` — CLI exit code based on any REQUIRED
  entries being unset
- `defenseclaw keys fill-missing` — interactive prompt loop over
  the REQUIRED+unset slice, masking existing values
- `defenseclaw doctor` — emits `fail` checks with the label
  `credential <ENV_NAME>` for any REQUIRED+unset credential
- `defenseclaw config show` — redacts any value whose key is
  recognized as a secret
- **TUI overview panel** — reads the cached doctor JSON and lifts
  the credential-labelled fails into a "keys: N missing" row plus
  a top-level notice (see "TUI surface" below)

Adding a new credential-gated feature requires one entry in
`CREDENTIALS`. All five surfaces update on the next invocation
without further code changes.

### Headless bootstrap

`cli/defenseclaw/bootstrap.py` extracts the idempotent portions of
`cmd_init.py`, `cmd_setup.py`, and the gateway start flow so
`quickstart` can run them in order without prompting. The
functions are deliberately narrow: `ensure_config_dir`,
`ensure_device_key`, `ensure_default_policies`, etc. Each is a
pure "create if missing, verify, return a status string" op.

`defenseclaw quickstart --non-interactive --yes` runs them in the
intended order, prints a single pass/fail table, and exits with a
non-zero code only if something that *needs* the user's attention
happened (e.g. no API keys for the guardrail model the operator
already picked).

### Lifecycle commands

| Command | What it does | Safety rails |
|---|---|---|
| `defenseclaw quickstart` | Headless init → setup → OpenClaw patch → gateway start → doctor summary. Re-runnable. | Honours existing config; never overwrites `.env`. |
| `defenseclaw keys check` | Exit non-zero when REQUIRED credentials are unset. | Read-only. |
| `defenseclaw keys inspect` | Table of every credential, its requirement, its source. | Values masked except last 4 chars. |
| `defenseclaw keys set NAME` | Write a single key to `.env`. | `.env` is `chmod 0o600` after every write. |
| `defenseclaw keys fill-missing` | Interactive loop over REQUIRED+unset entries. | Uses `click.prompt(hide_input=True)`, no value is echoed. |
| `defenseclaw config show` | Render active config with secrets redacted. | Never writes. |
| `defenseclaw config validate` | Load + schema-validate config.yaml. | Never writes. |
| `defenseclaw doctor --fix` | Run modular fixers (stale PIDs, gateway token, dotenv perms, pristine openclaw.json backup). | Each fixer is independent; a failure in one does not abort the rest. Honours `--yes` / no-op otherwise. |
| `defenseclaw uninstall --dry-run` | Preview what would be removed. | Default is dry-run. |
| `defenseclaw uninstall --confirm` | Remove the plugin, restore pristine `openclaw.json`, delete `~/.defenseclaw/`. | Refuses if the target dir lacks DefenseClaw marker files (`config.yaml`, `audit.db`, `policies/`, `quarantine/`). |
| `defenseclaw reset` | `uninstall` + `init` in one, for "wipe and start over" flows. | Same safety rails as `uninstall`. |
| `defenseclaw version` | CLI / gateway / plugin versions, with drift warnings. | Read-only. |

### Install scripts and Makefile

`scripts/install.sh` (release) and `scripts/install-dev.sh` (from
source) both accept `--quickstart` / `--quickstart-mode`. The
top-level `Makefile` adds five new targets:

- `make all` → `install` + `path` + `quickstart`
- `make path` → run `scripts/add-to-path.sh` (honours `YES=1`)
- `make doctor`, `make uninstall`, `make quickstart` — thin
  wrappers over the CLI that fall through to the venv binary if
  the installed symlink is missing (e.g. after `make clean`)

`scripts/add-to-path.sh` is shell-aware (`bash`, `zsh`, `fish`),
idempotent (checks for the exact export block it would append),
and prompts once per shell unless `--yes` is passed. The POSIX
compatibility layer uses `case` statements so `dash` / `sh`
invocations don't blow up on `[[`.

### TUI surface

The TUI's Overview panel already caches `defenseclaw doctor
--json-output` (P3-#21). We extend the existing cache with two
low-cost reads:

1. `DoctorCache.MissingRequiredCredentials()` scans the cached
   checks for the `credential <ENV_NAME>` emission pattern used by
   `_check_registry_credentials` in `cmd_doctor.py`. Returns the
   env-name slice in emission order.
2. The SCANNERS box gains a "keys" row derived from (1): a green
   `all required set` line when the slice is empty, a red
   `N missing: FOO, BAR (+2 more)` line otherwise.
3. `buildNotices` promotes a non-empty slice into a top-of-panel
   error notice pointing at `defenseclaw keys fill-missing`.

Because the TUI reads the cache and never re-probes the credential
registry itself, these surfaces cost nothing at render time.
Staleness is the operator's responsibility — the existing
"cache is stale" banner already nudges them.

We deliberately did not ship a TUI-native key-entry form. The CLI
`keys fill-missing` command is the canonical interactive surface;
recreating it inside bubbletea would require secure-input
rendering, keystroke pass-through, and prompt state machines that
duplicate Click. If telemetry later shows operators wanting an
in-TUI entry UX, the natural follow-up is a key-binding that
shells out to `defenseclaw keys fill-missing` in a sub-shell.

## Security considerations

### Path handling in `uninstall`

`_remove_data_dir` recursively deletes the configured `data_dir`.
An operator with a misconfigured `DEFENSECLAW_HOME=/` would have
previously asked the helper to `rm -rf /`. We now:

1. Resolve the real path and refuse `/` or `$HOME`.
2. Require at least one of `config.yaml`, `audit.db`, `.env`,
   `policies/`, `quarantine/` to exist in the target directory
   before invoking `shutil.rmtree`.
3. Print the refusal reason so the operator can correct the
   environment and re-run.

### `.env` permissions

`cli/defenseclaw/commands/cmd_setup.py::_write_dotenv` now calls
`os.chmod(path, 0o600)` unconditionally after each write, not
only on initial creation. This closes the case where a previous
write created the file with a looser umask (or the operator
`chmod 644`'d it manually) and subsequent writes inherited those
permissions.

### Device-key race

`_ensure_device_key` in `cmd_init.py` previously opened the PEM
with the default umask before chmod-ing to `0o600`. We now use
`os.open(path, O_WRONLY|O_CREAT|O_EXCL, 0o600)` so the file is
atomic and world-unreadable from the moment it exists. A
`FileExistsError` shortcircuits to the idempotent happy path.

### `keys set` input handling

`defenseclaw keys set` reads values via
`click.prompt(hide_input=True)` and writes via the hardened
`_write_dotenv`. We do not log the value anywhere; exception
messages are truncated and never include the payload.

### Doctor `--fix` scope

Every fixer is explicitly scoped to a single config-owned file:

- `_fix_stale_pid` — only touches `gateway.pid` when the PID is
  dead
- `_fix_openclaw_token` — regenerates the token we wrote, never
  mutates other OpenClaw fields
- `_fix_dotenv_perms` — chmod-only
- `_fix_pristine_backup` — creates a backup if none exists; never
  overwrites

No fixer restarts the gateway or mutates `openclaw.json` beyond
what `setup guardrail` would do.

## Testing

- **Python**: `cli/tests/test_credentials.py`, `test_bootstrap.py`,
  `test_cmd_config.py`, `test_cmd_keys.py`,
  `test_cmd_uninstall.py`, `test_cmd_version.py` exercise each new
  module in isolation with a `CliRunner`. The full `make
  cli-test-cov` run stays green.
- **Go**: new TUI tests in `overview_keys_test.go` plus the
  unit-level `DoctorCache.MissingRequiredCredentials` suite cover
  the all-set / missing / overflow / no-cache branches. The
  pre-existing `cli_parity_test.go` gates that every CLI command
  remains reachable from the TUI's command palette.
- **Scripts**: `scripts/add-to-path.sh` is linted with `shellcheck`
  and exercised end-to-end via `make all` in CI (GitHub runners
  provide `bash`, `zsh`, and `dash`).

## Rollout

1. Ship the gofmt baseline first so the subsequent commits stay
   legible on diff review.
2. Land the CLI UX commit (new commands + registry + bootstrap)
   alongside the `install.sh` / `install-dev.sh` / `Makefile`
   changes so `make all` and the scripts move together.
3. Land the TUI overview surface on top.
4. Land this RFC and update `docs/TUI.md` / `docs/CLI.md` cross-
   references.

No data migration is required. Existing `~/.defenseclaw/config.yaml`
files continue to load; new features are opt-in and gated by
config. The first `defenseclaw doctor` run after upgrading will
populate the credential registry surface automatically.

## Alternatives considered

- **Ship a bubbletea key-entry wizard**: higher UX ceiling but
  duplicates Click prompt handling, adds a secure-input surface
  that is non-trivial to get right in lipgloss, and makes the
  CLI ↔ TUI parity story harder. Deferred pending user demand.
- **Store secrets in the OS keychain**: attractive on macOS but
  poor fit for headless Linux CI where `keyring` falls back to
  plaintext files anyway. `.env` with `0o600` is a known quantity.
- **Ship uninstall as a `scripts/uninstall.sh`**: couldn't share
  the marker-file safety check with the CLI, and forces users
  back to the filesystem. Keeping everything under
  `defenseclaw …` keeps the mental model small.
