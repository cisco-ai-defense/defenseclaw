# Scan-Driven Capability Policy Auto-Generation

**Date:** 2026-04-08
**Status:** Approved
**Scope:** v1 — auto-generate `.capability.yaml` files when skills/MCP servers pass the admission gate, with manifest introspection, scan-informed posture, and approve workflow
**Depends on:** Capability-Based Access Control (2026-04-08)

## Problem

The capability-based access control system requires manually authored `.capability.yaml` files per agent. When a new skill or MCP server is installed, users must:

1. Know the system exists
2. Know what tools the skill/MCP exposes
3. Write a YAML manifest from scratch
4. Place it in the right directory

Until they do, the default-deny evaluator blocks everything. This creates friction: either users never set up policies (and the feature is dead), or they write overly permissive wildcard policies to unblock themselves.

## Goal

Automatically generate capability policies when skills/MCP servers pass the admission gate. Policies are scan-informed (security posture adapts to findings), introspect manifests for per-tool granularity, and require explicit user approval before the warning clears.

## Key Design Decisions

- **Watcher-integrated** — generator hooks into `runAdmission()` after verdict, no new goroutines or services
- **Scan-informed posture** — clean scans get permissive policies, findings trigger restrictions
- **Manifest introspection with fallback** — parse MCP `tools[]` / skill `permissions` when available, fall back to wildcards
- **Same directory, naming convention** — `auto-<name>.capability.yaml` in `~/.defenseclaw/capabilities/`
- **Semi-blocking approval** — policy is active immediately but TUI/CLI shows warning until `capability approve <agent>`
- **Approve renames file** — `auto-<name>` becomes `<name>`, marking user ownership

## Architecture

### Generation Flow

```
Skill/MCP detected → Scan → Admission verdict
    │
    ├─ Blocked/Rejected → no policy generated
    │
    └─ Clean/Warning/Allowed
         │
         ├─ Check: manual policy already exists? → skip
         │
         └─ Introspect manifest → generate policy → write file
              │
              ├─ Write auto-<name>.capability.yaml
              ├─ Log audit event (capability_generated)
              └─ Reload evaluator
```

### Approval Flow

```
User runs: defenseclaw capability approve <agent>
    │
    ├─ Find auto-<agent>.capability.yaml
    ├─ Rename to <agent>.capability.yaml
    ├─ Set approved: true in YAML
    ├─ Reload evaluator
    ├─ Log audit event (capability_approved)
    └─ TUI warning clears
```

## Manifest Introspection

### MCP Servers

MCP server manifests (JSON) contain a `tools` array:

```json
{
  "name": "weather-service",
  "tools": [
    {
      "name": "get_weather",
      "description": "Get current weather",
      "parameters": { "location": { "type": "string" } }
    }
  ]
}
```

`IntrospectMCP(path string) ([]ToolInfo, error)` parses this and returns per-tool metadata.

### Skills

Skill manifests (`skill.yaml`) declare capabilities and permissions:

```yaml
name: clean-skill
permissions:
  - read-only
```

`IntrospectSkill(path string) (*SkillInfo, error)` parses this and returns the name and permissions list. Skills don't declare individual tools, so they get wildcard resources (`skill-name.*`).

### Fallback

If introspection fails (no manifest found, malformed file), the generator falls back to a single wildcard capability: `<name>.*` with no constraints. This ensures a policy is always generated.

### Types

```go
type ToolInfo struct {
    Name        string
    Description string
    Parameters  map[string]any
}

type SkillInfo struct {
    Name        string
    Permissions []string
}
```

**New file:** `internal/capability/introspect.go`

Functions:
- `IntrospectMCP(path string) ([]ToolInfo, error)`
- `IntrospectSkill(path string) (*SkillInfo, error)`

## Policy Generation Logic

### Scan-Informed Posture

The generator uses `ScanResult.MaxSeverity()` to determine the security posture:

| Scan Result | Posture | Capabilities | Restrictions | Rate Limit |
|-------------|---------|-------------|--------------|------------|
| Clean (no findings) | Permissive | All discovered tools, no constraints | None | None |
| LOW/MEDIUM findings | Cautious | All discovered tools, no constraints | `no_bulk_export` | 100 calls / 3600s |
| HIGH/CRITICAL findings | Restrictive (safety net) | Read-like tools only (`get_*`, `list_*`, `read_*`, `search_*`) | `no_write`, `no_delete`, `no_bulk_export` | 50 calls / 3600s |

HIGH/CRITICAL should not normally reach the generator (admission gate blocks them), but the restrictive posture exists as a safety net for edge cases (e.g., allow-listed items that had findings).

### Read-Like Tool Detection

A tool is considered read-like if its name starts with one of: `get_`, `list_`, `read_`, `search_`, `fetch_`, `query_`, `describe_`, `show_`.

### Skill Permission Mapping

If a skill declares `permissions: [read-only]`, add `no_write` and `no_delete` restrictions regardless of scan posture.

### Generated Policy Structure

```yaml
agent: auto-weather-service
description: "Auto-generated from MCP scan (clean)"
generated: true
approved: false

capabilities:
  - name: get_weather
    resource: "weather-service.get_weather"
    constraints: {}

restrictions: []

conditions: {}
```

### Generator Interface

```go
// GenerateRequest bundles the inputs for policy generation.
// Uses primitive types to avoid circular dependency with watcher package.
type GenerateRequest struct {
    Name       string           // skill/MCP name (from InstallEvent.Name)
    Type       string           // "skill" or "mcp" (from InstallEvent.Type)
    Tools      []ToolInfo       // from introspection (nil if introspection failed)
    SkillInfo  *SkillInfo       // from skill introspection (nil for MCP)
    ScanResult *ScanResultSummary // scan posture summary
}

// ScanResultSummary is a lightweight view of scanner.ScanResult
// to avoid importing the scanner package.
type ScanResultSummary struct {
    MaxSeverity   string // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", ""
    TotalFindings int
}

func GeneratePolicy(req GenerateRequest) *AgentPolicy
```

The watcher constructs `GenerateRequest` from its local `InstallEvent` and `ScanResult`, keeping the `capability` package free of watcher/scanner imports.

**New file:** `internal/capability/generator.go`

## Type Changes

### AgentPolicy (types.go)

Add two new fields:

```go
type AgentPolicy struct {
    Agent        string       `yaml:"agent"`
    Description  string       `yaml:"description"`
    Generated    bool         `yaml:"generated,omitempty"`
    Approved     bool         `yaml:"approved,omitempty"`
    Capabilities []Capability `yaml:"capabilities"`
    Restrictions []string     `yaml:"restrictions"`
    Conditions   Conditions   `yaml:"conditions"`
}
```

The evaluator ignores `Generated` and `Approved` — they are metadata for CLI/TUI only. The evaluation pipeline is unchanged: if a policy exists and matches, it allows; if not, it denies.

## Watcher Integration

### Changes to `internal/watcher/watcher.go`

Add fields to `Watcher` struct:

```go
type Watcher struct {
    // ... existing fields ...
    capabilityDir  string
    capEvaluator   *capability.Evaluator
}
```

In `runAdmission()`, after enforcement actions are applied (post-verdict), add:

```go
if verdict == VerdictClean || verdict == VerdictWarning || verdict == VerdictAllowed {
    w.generateCapabilityPolicy(evt, result)
}
```

New method `generateCapabilityPolicy(evt InstallEvent, result *ScanResult)`:

1. Check if a manual policy already exists for this agent name (no `auto-` prefix) — if so, skip
2. Check if an auto-generated policy already exists — if so, skip (don't overwrite)
3. Introspect manifest based on `evt.Type` (skill vs MCP)
4. Call `GeneratePolicy()` with introspection results and scan result
5. Marshal to YAML and write to `<capabilityDir>/auto-<name>.capability.yaml`
6. Log `capability_generated` audit event
7. Reload evaluator via `capEvaluator.Reload()`

### Passing ScanResult to Generator

The `ScanResult` is already available in `runAdmission()` as a local variable (`result`). It's computed before the verdict and used for the OPA policy evaluation. The generator call site has direct access to it — no plumbing changes needed.

## CLI: `capability approve` Command

### Addition to `internal/cli/capability.go`

```
defenseclaw capability approve <agent>
```

Steps:
1. Find `auto-<agent>.capability.yaml` in `cfg.CapabilityPolicyDir`
2. If not found, return error: `no pending auto-generated policy for "<agent>"`
3. Read the YAML, set `approved: true`
4. Write to `<agent>.capability.yaml` (new name, same directory)
5. Remove the old `auto-<agent>.capability.yaml`
6. Reload evaluator
7. Log `capability_approved` audit event
8. Print: `Approved: <agent> (<N> capabilities, <M> restrictions)`

## TUI: Agents Panel Status Column

### Changes to `internal/tui/agents.go`

The `AgentsPanel` currently aggregates from audit store decisions only. Add policy awareness:

- Accept `policies map[string]*AgentPolicy` in a new `SetPolicies()` method
- Add `Status` field to `AgentItem`: `"approved"`, `"pending review"`, or `"manual"`
  - `generated == true && approved == false` → `"pending review"`
  - `generated == true && approved == true` → `"approved"`
  - `generated == false` (or field absent) → `"manual"`
- Display status in the table with color coding:
  - `pending review` — yellow
  - `approved` / `manual` — default

### Changes to `internal/tui/app.go`

- Pass evaluator's `Policies()` to `agents.SetPolicies()` during `refresh()`
- Requires the `Model` to hold a reference to the capability evaluator (or just its policies)

## Audit Events

Two new audit events using existing `auditLog.LogEvent()`:

| Event Action | Target | Severity | Details |
|-------------|--------|----------|---------|
| `capability_generated` | agent name | INFO | `"posture=permissive, capabilities=3, source=mcp-introspect"` |
| `capability_approved` | agent name | INFO | `"capabilities=3, restrictions=0"` |

## Conflict and Edge Case Handling

- **Manual policy exists:** Skip auto-generation entirely. Manual always wins.
- **Auto policy already exists:** Skip. Don't overwrite on re-scan. User must delete to trigger re-generation.
- **Introspection fails:** Fall back to wildcard `<name>.*` capability with scan-informed posture.
- **Skill with no permissions field:** Treat as unconstrained (no restrictions from permissions).
- **MCP with empty tools array:** Generate single wildcard `<name>.*` capability.
- **Approve when auto file doesn't exist:** Return clear error message.
- **Approve when manual file already exists:** Return error — user should edit the manual file directly.

## Testing Strategy

### Unit Tests (`test/unit/`)

**`capability_introspect_test.go`:**
- Parse valid MCP manifest with 3 tools → returns 3 ToolInfo
- Parse MCP manifest with no tools array → returns empty slice
- Parse malformed MCP JSON → returns error
- Parse valid skill.yaml with permissions → returns SkillInfo with permissions
- Parse skill.yaml without permissions → returns SkillInfo with empty permissions
- Parse missing file → returns error

**`capability_generator_test.go`:**
- Clean scan + 3 MCP tools → permissive policy with 3 capabilities, no restrictions
- MEDIUM scan + 3 MCP tools → cautious policy with 3 capabilities, `no_bulk_export`, rate limit
- HIGH scan + mixed tools (get_x, create_y, delete_z) → restrictive policy with only get_x, plus restrictions
- No tools (fallback) → wildcard `<name>.*` capability
- Skill with `read-only` permission → adds `no_write`, `no_delete` restrictions
- All generated policies have `Generated: true, Approved: false`

**`capability_approve_test.go`:**
- Auto file exists → rename succeeds, approved set to true
- No auto file → returns error
- Manual file already exists → returns error (skip)

### Test Fixtures (`test/fixtures/`)

- `test/fixtures/mcps/tools-mcp.json` — 3 tools (get_weather, create_alert, delete_alert)
- `test/fixtures/mcps/no-tools-mcp.json` — empty tools array
- `test/fixtures/skills/permissioned-skill/skill.yaml` — has `permissions: [read-only]`

## Files to Create/Modify

### New Files (6 + 3 fixtures)
- `internal/capability/introspect.go` — MCP/skill manifest parsing
- `internal/capability/generator.go` — scan-informed policy generation
- `test/unit/capability_introspect_test.go` — introspection tests
- `test/unit/capability_generator_test.go` — generation logic tests
- `test/unit/capability_approve_test.go` — approve workflow tests
- `test/fixtures/mcps/tools-mcp.json`
- `test/fixtures/mcps/no-tools-mcp.json`
- `test/fixtures/skills/permissioned-skill/skill.yaml`

### Modified Files (5)
- `internal/capability/types.go` — add `Generated`, `Approved` fields to `AgentPolicy`
- `internal/watcher/watcher.go` — add `capabilityDir`, `capEvaluator` fields; call generator in `runAdmission()`
- `internal/cli/capability.go` — add `approve` subcommand
- `internal/tui/agents.go` — add `SetPolicies()`, status column, color coding
- `internal/tui/app.go` — pass evaluator policies to agents panel on refresh

## Future Iterations (Out of Scope)

- **Runtime learning mode** — observe `tool_call` events to refine constraints based on actual usage patterns
- **Constraint inference from parameters** — use MCP parameter schemas to auto-generate constraints (e.g., enum values → list constraints)
- **Policy diff on re-scan** — when a skill is updated and re-scanned, show what changed vs. the current policy
- **Bulk approve** — `capability approve --all` for approving all pending policies at once
- **Policy templates** — user-defined templates that auto-generation uses instead of the built-in posture rules
