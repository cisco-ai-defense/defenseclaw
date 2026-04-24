# Connector Architecture v3 — Executive Summary

**Commit**: `39afe5a` on `feature/connector-architecture-v3`
**Date**: 2026-04-24
**Scope**: `internal/gateway/connector/`, `internal/gateway/proxy.go`, `internal/gateway/proxy_test.go`

---

## Overview

This commit delivers a comprehensive code review and hardening pass across the DefenseClaw connector package. A background code review agent identified 18 findings across the connector architecture. 12 findings were fixed in this commit, plus a new feature (connector prefix routing) was discovered as missing during end-to-end testing and implemented. The remaining 6 findings are documented in `docs/CONNECTOR-REMAINING-FIXES.md` for follow-up.

---

## Changes by Category

### Critical Fixes (2)

**1. `removeOwnedHooks` slice truncation bug** (`claudecode.go`)
- **Before**: Function returned `nil` when removing hooks, causing the parent map to retain stale entries with nil-padded slices. Go slices accessed through a type-asserted `interface{}` cannot be shrunk in-place — the caller never sees the shortened slice.
- **After**: Returns the truncated slice `list[:n]`, and the call site assigns it back: `hooks[key] = removeOwnedHooks(hk)`.

**2. Invalid `UserPromptExpansion` hook event removed** (`claudecode.go`)
- `UserPromptExpansion` is not a valid Claude Code hook event. Registering it caused silent failures during hook setup. Removed from `hookGroups`. The valid set is now 8 events: PreToolUse, PostToolUse, PreCompact, PostCompact, UserPromptSubmit, SessionStart, Stop, SubagentStop.

### High-Severity Fixes (3)

**3. Non-curl shims resolve `curl` past shim directory** (`shims/nc.sh`, `wget.sh`, `ssh.sh`, `pip.sh`, `npm.sh`)
- **Problem**: Shim scripts called `curl` to send inspection requests to the gateway, but `curl` itself was shimmed. This caused infinite recursion (double-inspection).
- **Fix**: Each non-curl shim now strips its own shim directory from `$PATH` before resolving `curl`:
  ```bash
  CURL_BIN=$(PATH="$(echo "$PATH" | sed "s|${SHIM_DIR}:||g; s|:${SHIM_DIR}||g")" which curl 2>/dev/null || echo /usr/bin/curl)
  ```

**4. `--argjson` → `--arg` in hook scripts** (`hooks/inspect-tool.sh`, `hooks/inspect-tool-response.sh`)
- `jq --argjson` requires valid JSON input. Tool output and arguments are often plain text, not JSON. Changed to `--arg` which wraps the value as a JSON string automatically.

**5. ZeptoClaw `api_base` backup/restore** (`zeptoclaw.go`)
- **Before**: Setup overwrote `api_base` in ZeptoClaw's config to point at the proxy, but teardown didn't restore the original value. If the user had a custom `api_base`, it was permanently lost.
- **After**: Backup struct now includes `OriginalAPIBase` and `HadAPIBase` fields. Teardown restores the original value or removes the key if it didn't exist before setup.

### Medium-Severity Fixes (5)

**6. `TeardownSubprocessEnforcement` removes individual files, not shared directories** (`subprocess.go`)
- Previously removed the entire `hooks/` directory, which could delete user-created hook scripts. Now removes only the specific files DefenseClaw created (shim directory, named hook scripts, policy file).

**7. `IsLoopback` uses proper IP parsing** (`helpers.go`)
- Replaced string comparison (`remoteAddr == "127.0.0.1"`) with `net.SplitHostPort` + `net.ParseIP().IsLoopback()`. Handles IPv6 loopback (`::1`), port-suffixed addresses, and `localhost` hostname.

**8. Backup skip-if-exists prevents crash+re-setup overwrite** (`claudecode.go`)
- If DefenseClaw crashed mid-setup and the user re-ran setup, the backup file would be overwritten with the already-patched config, making restoration impossible. Now checks `os.Stat(backupPath)` and skips if the backup already exists.

**9. `isChatPath` moved from `openclaw.go` to `helpers.go`** (`helpers.go`, `openclaw.go`)
- Shared utility function was defined in a connector-specific file. Moved to `helpers.go` where it's accessible to all connectors.

**10. Dead code removal** (`openclaw.go`)
- Removed unused `openclawBackup` type and its `saveBackup`/`loadBackup` methods. Cleaned up imports (`encoding/json`, `os`).

### New Feature: Connector Prefix Routing

**11. `/c/<name>/` prefix stripping middleware** (`proxy.go`, `proxy_test.go`)
- **Discovery**: End-to-end testing revealed that requests to `/c/claudecode/v1/messages` and `/c/zeptoclaw/v1/chat/completions` returned 400 errors because no handler matched these paths.
- **Implementation**: Added `connectorPrefixStripper` middleware that strips `/c/<name>/` prefixes before routing:
  - `/c/claudecode/v1/messages` → `/v1/messages`
  - `/c/zeptoclaw/v1/chat/completions` → `/v1/chat/completions`
  - `/c/openclaw/api/v1/inspect/tool` → `/api/v1/inspect/tool`
- **Tests**: 9 test cases covering all connector names, nested paths, unknown connectors, and edge cases (bare `/c/`, no trailing path).

### Test Updates

**12. `connector_test.go` expected events list updated**
- Removed `UserPromptExpansion` from `expectedEvents` to match the corrected `hookGroups`.

---

## End-to-End Test Results

All 20 tests pass across 4 inspection surfaces with guardrail `mode=action` (blocking):

| Surface | Tests | Result |
|---------|-------|--------|
| Claude Code Hook (`/api/v1/claude-code/hook`) | 6 | All pass |
| Inspect Endpoints (`/api/v1/inspect/*`) | 6 | All pass |
| LLM Proxy (Anthropic + OpenAI formats) | 4 | All pass |
| Connector Prefix Routing (`/c/<name>/`) | 4 | All pass |

**Test categories**:
- Prompt injection detection and blocking
- Data exfiltration command blocking
- API key/secret leakage detection
- Benign content pass-through
- Cross-format support (Anthropic Messages + OpenAI Chat Completions)

---

## Remaining Work

6 findings require design decisions or non-trivial implementation. Full details in `docs/CONNECTOR-REMAINING-FIXES.md`:

| # | Severity | Summary | Effort |
|---|----------|---------|--------|
| 6 | HIGH | Only 8 of 22+ techspec events registered | 2-3h (needs event list decision) |
| 7 | HIGH | HandleHookEvent is a stub (always allows) | 30min or 2-3d (needs architecture decision) |
| 12 | MEDIUM | InstallScope + FailClosed config not implemented | 2-3h |
| 8 | MEDIUM | X-DC-Auth Bearer prefix handling inconsistency | 30min |
| 9 | MEDIUM | No file locking on settings.json read-modify-write | 1-2h |
| 14 | MEDIUM | Global test override variables are exported/fragile | 1h |

---

## Files Changed

```
internal/gateway/connector/claudecode.go        — removeOwnedHooks fix, hookGroups cleanup, backup protection
internal/gateway/connector/zeptoclaw.go          — api_base backup/restore
internal/gateway/connector/subprocess.go         — safe teardown (individual file removal)
internal/gateway/connector/helpers.go            — IsLoopback fix, isChatPath moved here
internal/gateway/connector/openclaw.go           — dead code removal, import cleanup
internal/gateway/connector/hooks/inspect-tool.sh — --argjson → --arg
internal/gateway/connector/hooks/inspect-tool-response.sh — --argjson → --arg
internal/gateway/connector/shims/nc.sh           — curl resolution past shim dir
internal/gateway/connector/shims/wget.sh         — curl resolution past shim dir
internal/gateway/connector/shims/ssh.sh          — curl resolution past shim dir
internal/gateway/connector/shims/pip.sh          — curl resolution past shim dir
internal/gateway/connector/shims/npm.sh          — curl resolution past shim dir
internal/gateway/connector/connector_test.go     — expected events list update
internal/gateway/proxy.go                        — connectorPrefixStripper middleware
internal/gateway/proxy_test.go                   — 9 prefix stripping test cases
docs/CONNECTOR-REMAINING-FIXES.md                — 6 remaining findings documented
```
