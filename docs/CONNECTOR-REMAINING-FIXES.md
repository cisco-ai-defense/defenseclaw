# Connector Package — Remaining Fixes

**Date**: 2026-04-28 (updated by PR #194 single rollup)
**Package**: `internal/gateway/connector/`
**Review base**: Full code review against techspec, 18 findings total, 12 fixed.

This document tracks the remaining findings from the connector code review that require design decisions, architectural alignment, or non-trivial implementation work.

## PR #194 single-rollup status (2026-04-28)

Items resolved in this rollup are marked DONE inline below. Items
that remain open continue to track what's deferred to follow-up
PRs. See `CHANGELOG.md` for the full set of changes; this file
focuses on the connector-package review thread.

| # | Severity | Status as of PR #194 |
|---|----------|----------------------|
| 6  | HIGH    | OPEN — needs event-list decision |
| 7  | HIGH    | DONE (Option A) — `HookEventHandler` interface deleted via Phase A5; gateway-level dispatcher is the canonical owner |
| 8  | MEDIUM  | OPEN — chose pragmatic Option C (test added) |
| 9  | MEDIUM  | DONE — `withFileLock` + atomic-rename helpers in `helpers.go` |
| 12 | MEDIUM  | OPEN — needs config-schema decision |
| 14 | MEDIUM  | OPEN — `*PathOverride` globals retained for now; SetupOpts plumbing tracked as a follow-up |

---

## Fixed (for reference)

| # | Severity | Summary |
|---|----------|---------|
| 1 | CRITICAL | `removeOwnedHooks` now returns truncated slice instead of nil-padding |
| 2 | CRITICAL | Call site assigns returned slice to parent map |
| — | CRITICAL | Removed invalid `UserPromptExpansion` hook event |
| 3 | HIGH | 5 non-curl shims resolve `curl` past shim dir to avoid double-inspection |
| 4 | HIGH | `inspect-tool.sh` / `inspect-tool-response.sh` use `--arg` instead of `--argjson` |
| 5 | HIGH | ZeptoClaw backup/restore preserves pre-existing `api_base` |
| 10 | MEDIUM | `TeardownSubprocessEnforcement` removes individual files, not shared `hooks/` dir |
| 11 | MEDIUM | `IsLoopback` uses `net.SplitHostPort` + `net.ParseIP().IsLoopback()` |
| 13 | MEDIUM | Backup skip-if-exists prevents crash+re-setup from overwriting clean backup |
| 17 | LOW | `isChatPath` moved from `openclaw.go` to `helpers.go` |
| 18 | LOW | Removed dead `openclawBackup` type and unused save/load methods |

---

## Remaining: Requires Design Decision

### #6 — HIGH: Only 8 of 22+ techspec events registered in hookGroups

**File**: `claudecode.go:226-239`

**Current state**: `hookGroups` registers 8 events: `PreToolUse`, `PostToolUse`, `PreCompact`, `PostCompact`, `UserPromptSubmit`, `SessionStart`, `Stop`, `SubagentStop`.

**Missing events from techspec** (Section 5c):

| Event | Security relevance | Suggested priority |
|-------|-------------------|-------------------|
| `PermissionRequest` | Gates permission escalation in action mode | P0 — security-critical |
| `PermissionDenied` | Audit trail for denied permissions | P1 |
| `SessionEnd` | Session teardown scanning | P1 |
| `InstructionsLoaded` | Detect instruction injection | P1 |
| `SubagentStart` | Track subagent spawning | P1 |
| `StopFailure` | Detect abnormal termination | P2 |
| `ConfigChange` | Detect runtime config manipulation | P2 |
| `FileChanged` | Track file mutations | P2 |
| `CwdChanged` | Track directory traversal | P2 |
| `TaskCreated` | Task lifecycle audit | P3 |
| `TaskCompleted` | Task lifecycle audit | P3 |
| `TeammateIdle` | Multi-agent coordination audit | P3 |
| `Elicitation` | User interaction tracking | P3 |
| `ElicitationResult` | User interaction tracking | P3 |
| `Notification` | Informational, low value | P3 |
| `Setup` | Session initialization | P3 |

**Decision needed**: Which events to register and at what inspection depth (block/observe/audit-only). Not all events need the same treatment — `PermissionRequest` should support blocking, while `Notification` may only need audit logging.

**Implementation**:
1. Add entries to `hookGroups` in `claudecode.go` (one line each)
2. Add dispatch cases in `evaluateClaudeCodeHook()` in `claude_code_hook.go`
3. Define OPA policy stubs for new events
4. Update `connector_test.go` expected events list

**Effort**: ~2-3 hours code once the event list is decided.

---

### #7 — HIGH: HandleHookEvent is a stub (always returns "allow")

**Files**:
- `claudecode.go:145-157`
- `codex.go:130-142`

**Current state**: Both connectors' `HandleHookEvent` parses the event name but always returns `{"action": "allow"}`. No inspection dispatch, no policy evaluation, no PII redaction.

**Context**: The *real* inspection logic lives at the gateway level in `claude_code_hook.go:evaluateClaudeCodeHook()`, which dispatches to OPA policies, PII scanning, etc. The hook shell script (`claude-code-hook.sh`) calls the gateway's `/api/v1/claude-code/hook` endpoint, which is handled by the gateway — not the connector's `HandleHookEvent`.

**Decision needed**: Clarify the intended architecture:

- **Option A** (likely current design): The gateway-level handler owns inspection dispatch. The connector's `HandleHookEvent` is a fallback/interface stub. In this case, document it and consider removing the `HookEventHandler` interface from connectors entirely, since the gateway handles it.

- **Option B**: Move inspection dispatch into the connector so each connector owns its full inspection pipeline. This is a significant refactor (~2-3 days) and changes the gateway's role from "inspection orchestrator" to "connector router".

**Effort**: 30 min if Option A (document + clarify). 2-3 days if Option B.

---

### #12 — MEDIUM: InstallScope and FailClosed config fields not implemented

**File**: `claudecode.go` (Setup method), hook script templates

**Techspec reference**: Section 22c

**InstallScope** (`"user"` | `"repo"`):
- `"user"` (default): hooks go in `~/.claude/settings.json`
- `"repo"`: hooks go in `<cwd>/.claude/settings.json`
- Currently `claudeCodeSettingsPath()` always uses `$HOME/.claude/settings.json`

**FailClosed** (bool):
- When true, hook scripts should `exit 2` (block) when the gateway is unreachable
- Currently all hook scripts fail open: `|| { exit 0 }`
- Requires conditional templating in hook scripts or a template variable

**Implementation**:
1. Add `InstallScope` and `FailClosed` fields to config struct
2. Plumb `InstallScope` through `SetupOpts` → `claudeCodeSettingsPath()`
3. Add `FailClosed` template variable to hook script templates
4. Update hook script templates: `|| { exit {{if .FailClosed}}2{{else}}0{{end}} }`
5. Add tests for both modes

**Effort**: 2-3 hours.

---

## Remaining: Code Hardening

### #8 — MEDIUM: X-DC-Auth Bearer prefix handling inconsistency

**Files**: All 4 connectors' `Authenticate` methods

**Current state**: `strings.TrimPrefix(dcAuth, "Bearer ")` accepts both `"my-token"` and `"Bearer my-token"` as valid. This is ambiguous — the fetch interceptor plugin sends the raw token, but the code also accepts prefixed form.

**Edge case**: If `gatewayToken` is `"Bearer foo"` and the header sends `"Bearer Bearer foo"`, `TrimPrefix` produces `"Bearer foo"` which matches. Unlikely but technically an auth bypass for a contrived token value.

**Fix options**:
- **A**: Always require `Bearer ` prefix — update fetch interceptor to send it, reject headers without it
- **B**: Never accept prefix — remove `TrimPrefix`, compare raw header value
- **C** (pragmatic): Keep current behavior, add a test documenting it, ensure gateway tokens never start with `"Bearer "`

**Effort**: 30 minutes for any option.

---

### #9 — MEDIUM: No file locking on settings.json / config.json read-modify-write

**Files**:
- `claudecode.go:244-311` (`patchClaudeCodeHooks`)
- `zeptoclaw.go:163-212` (`patchZeptoClawConfig`)

**Current state**: Read-modify-write cycle without file locking or atomic writes. If two `defenseclaw setup` processes run concurrently, or the user edits settings.json while setup runs, the last writer wins.

**Fix**:
1. Create an `atomicWriteFile(path, data, perm)` helper in `helpers.go`:
   - Write to a temp file in the same directory
   - `os.Rename` temp file over target (atomic on POSIX)
2. Optionally add `flock`-based advisory locking for the read-modify-write window
3. Replace `os.WriteFile` calls in both patchers

**Effort**: 1-2 hours.

---

### #14 — MEDIUM: Global test override variables are exported and fragile

**Files**:
- `claudecode.go:215` (`ClaudeCodeSettingsPathOverride`)
- `zeptoclaw.go:152` (`ZeptoClawConfigPathOverride`)

**Current state**: Package-level exported variables used by tests to redirect config paths. No `t.Parallel()` within the test file, so no race within this package. But exported globals are fragile — external packages or concurrent test runs could collide.

**Fix**: Move the settings path into `SetupOpts` as an optional field:

```go
type SetupOpts struct {
    DataDir           string
    ProxyAddr         string
    APIAddr           string
    Interactive       bool
    SettingsPathOverride string // optional, for testing
}
```

Then `claudeCodeSettingsPath()` checks `opts.SettingsPathOverride` first. Remove the global variables.

**Effort**: 1 hour. Touches `SetupOpts`, both connectors' Setup/Teardown, and all tests that set the override.

---

## Summary

| # | Severity | Category | Effort | Blocking? |
|---|----------|----------|--------|-----------|
| 6 | HIGH | Missing hook events | 2-3h (once decided) | Needs event list decision |
| 7 | HIGH | HandleHookEvent stub | 30min or 2-3d | Needs architecture decision |
| 12 | MEDIUM | InstallScope + FailClosed | 2-3h | Needs config schema decision |
| 8 | MEDIUM | Auth header consistency | 30min | No |
| 9 | MEDIUM | Atomic file writes | 1-2h | No |
| 14 | MEDIUM | Test isolation globals | 1h | No |

**Recommended order**:
1. Decide #7 (architecture) — this informs whether #6 events dispatch through the connector or gateway
2. Implement #6 (missing events) — biggest security coverage gap
3. Implement #9 (atomic writes) — prevents data loss
4. Implement #8, #14, #12 — hardening and config features
