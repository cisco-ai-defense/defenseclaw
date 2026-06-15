# Phase D4 — S8.1 / S8.2 / S8.3 Verification Log

**Date**: 2026-04-28
**Branch**: PR #194 single rollup base
**Verification target**: confirm S8.1 / S8.2 / S8.3 are actually
shipped to the release/connector-architecture-v3 branch via PRs
#167 / #168 / #171 — not just claimed by their commit titles.

Per Phase D / item 4 of the rollup plan: each finding gets a
specific test that exercises the production code path, NOT a
re-read of the merge commit. If any of the three regress, Phase F
supplies a pre-staged fallback.

## S8.1 (F31) — Codex env scoping

**Contract**: `connector.CodexConnector.Setup` patches
`[providers.openai].base_url` in `~/.codex/config.toml`. It does
NOT export a global `OPENAI_BASE_URL` to the user's shell rc, and
any pre-existing env-export file is captured into a backup before
removal.

**Verifying tests** (`internal/gateway/connector/`):

| Test                                              | Validates |
|---------------------------------------------------|-----------|
| `TestCodex_Setup_Surface1_DoesNotExportGlobalEnv` | The post-Setup env surface contains zero `OPENAI_BASE_URL` lines DefenseClaw could have written. |
| `TestCodex_Setup_Surface1_BackupsExistingEnv`     | A pre-existing `.zshrc` line is captured into the connector backup before being removed (so Teardown can restore it). |
| `TestCodex_Teardown_RemovesLegacyEnvFiles`        | Teardown removes any legacy env-shim files created before S8.1 landed. |

**Run**: passing as of 2026-04-28.

```sh
go test -count=1 -run \
  'TestCodex_Setup_Surface1_DoesNotExportGlobalEnv|TestCodex_Teardown_RemovesLegacyEnvFiles|TestCodex_Setup_Surface1_BackupsExistingEnv' \
  -v ./internal/gateway/connector/
```

**If this regresses**: drop into Phase F1. The fallback patches
`~/.codex/config.toml` `[providers.openai].base_url` atomically and
scopes any unavoidable env to `exec env OPENAI_BASE_URL=… codex …`
launchers — never to user shell rc.

## S8.2 (F32) — Setup writes only the picked agent

**Contract**: `defenseclaw setup guardrail --agent <name>` runs
exactly the picked connector's `Setup`. Other connectors' on-disk
config (e.g. `~/.claude/settings.json` when picking codex) is left
byte-identical.

**Verifying tests** (`cli/tests/test_guardrail.py`,
`TestSetupGuardrailCommand`):

| Test                                                       | Validates |
|------------------------------------------------------------|-----------|
| `test_picked_connector_hint_drives_default`                | `<data_dir>/picked_connector` (written by `install.sh --connector`) drives `setup guardrail` when no `--connector` flag is passed. |
| `test_picked_connector_hint_does_not_override_explicit_existing` | The hint cannot silently override a connector value the operator already saved into config.yaml. |
| `test_picked_connector_hint_invalid_value_is_ignored`      | Garbage in the hint file falls back to `openclaw`, not a crash. |

Plus the unit-test layer in `TestReadPickedConnector` covers the
hint-reader's edge cases (whitespace, empty file, missing dir).

**Run**: passing as of 2026-04-28.

```sh
python3 -m pytest cli/tests/test_guardrail.py -v -k "picked_connector"
```

**If this regresses**: drop into Phase F2. The fallback prunes
`setup guardrail`'s "shared setup-all" loop down to a single
`pickedConnector.Setup(opts)` invocation and adds a snapshot diff
test for the unselected connectors.

## S8.3 (F33) — Observe mode honored end-to-end

**Contract**: When `cfg.Guardrail.Mode = "observe"`, the proxy
inspect path returns `action=allow` even when the rule would have
matched a block, and the audit log records a
`would_have_blocked` event with the full reason string.

**Verifying tests** (`internal/gateway/`):

| Test                                              | Validates |
|---------------------------------------------------|-----------|
| `TestInspectToolObserveModeNeverBlocks`           | A known-block tool call (`curl piped to shell`) under observe mode emits an `OBSERVED` log line, returns `action=allow`, but stamps `raw_action=block` and `would_block=true` on the proxy event. |
| `TestHandleGuardrailEvaluate_FallbackObserveMode` | The guardrail evaluate handler falls back to `alert` (not `block`) under observe mode, and the audit row records both the actual decision and the would-be one. |

**Run**: passing as of 2026-04-28.

```sh
go test -count=1 -run \
  'TestInspectToolObserveModeNeverBlocks|TestHandleGuardrailEvaluate_FallbackObserveMode' \
  -v ./internal/gateway/
```

**If this regresses**: drop into Phase F3. The fallback updates the
shell hooks (`hooks/inspect-*.sh`) to read the `mode: observe`
header from the gateway response and exit 0 + emit a
`would_have_blocked` audit line, instead of exit 2 + block.

## Summary

| Finding | Status | Tests |
|---------|--------|-------|
| S8.1    | ✅ shipped to base | 3 Go tests pass |
| S8.2    | ✅ shipped to base | 3 Python tests pass |
| S8.3    | ✅ shipped to base | 2 Go tests pass |

Phase F is **not triggered**. The pre-staged F1/F2/F3 commits are
left in the plan for completeness but do not need to land in this
rollup.
