# Capability-Based Access Control for Defenseclaw

**Date:** 2026-04-08
**Status:** Approved
**Scope:** v1 — static constraints + time/environment/rate conditions, allow/deny decisions, sidecar/hook integration

## Problem

Defenseclaw currently enforces tool-level block/allow decisions through scan-based admission gates. This is too coarse: an agent either has access to an entire MCP server/tool or it doesn't. There is no way to express "agent X can read Jira tickets in project ENG but not write to them" or "agent Y can post to #support but not #general."

## Goal

Granular control over tools, skills, and MCP servers available to an agent via **capability-based access control with runtime enforcement**. Agents don't get tools — they get constrained capabilities enforced at runtime.

## Key Design Decisions

- **Sidecar/hook mode** — integrates with existing daemon, no MCP proxy required
- **Separate capability manifests** — `.capability.yaml` files per agent, independent from scan policies
- **Static constraints + time/environment/rate limits** — no sequence detection or risk scoring in v1
- **Allow/Deny only** — no downscoping or escalation in v1
- **Default-deny** — if no capability matches, the call is denied
- **New `internal/capability` package** — standalone evaluator, clean separation from existing enforce/scan pipeline

## Architecture

### Enforcement Flow

```
Agent tool call → Hook event → Daemon receives
    │
    ├─ Capability Evaluator: Allow/Deny?
    │     └─ Deny → Log + reject (never reaches scan pipeline)
    │
    └─ Allow → Existing admission gate (block list → allow list → scan → decide)
```

Capability enforcement is the first check, before the existing scan flow. If an agent doesn't have the capability, there's no point scanning the tool for vulnerabilities.

## Core Types

### Agent Capability Manifest

Each agent gets a manifest file (e.g., `~/.defenseclaw/capabilities/support-bot.capability.yaml`):

```yaml
agent: support-bot
description: "Customer support automation agent"

capabilities:
  - name: read_jira_ticket
    resource: "jira.get_issue"
    constraints:
      project: "ENG-*"
      fields: ["summary", "status", "assignee"]

  - name: post_slack_message
    resource: "slack.post_message"
    constraints:
      channel: "#support"
      template: "approved_templates_only"

  - name: read_confluence
    resource: "confluence.get_page"
    constraints:
      space: "SUPPORT"

restrictions:
  - "no_external_http"
  - "no_bulk_export"

conditions:
  time_window: "09:00-18:00"
  environments: ["production", "staging"]
  rate_limit:
    max_calls: 100
    window_seconds: 3600
```

### Go Types (`internal/capability/types.go`)

```go
type AgentPolicy struct {
    Agent        string       `yaml:"agent"`
    Description  string       `yaml:"description"`
    Capabilities []Capability `yaml:"capabilities"`
    Restrictions []string     `yaml:"restrictions"`
    Conditions   Conditions   `yaml:"conditions"`
}

type Capability struct {
    Name        string         `yaml:"name"`
    Resource    string         `yaml:"resource"`
    Constraints map[string]any `yaml:"constraints"`
}

type Conditions struct {
    TimeWindow    string   `yaml:"time_window"`
    Environments  []string `yaml:"environments"`
    RateLimit     *Rate    `yaml:"rate_limit"`
}

type Rate struct {
    MaxCalls      int `yaml:"max_calls"`
    WindowSeconds int `yaml:"window_seconds"`
}
```

### Evaluation Request & Decision

```go
type EvalRequest struct {
    Agent       string
    Resource    string
    Params      map[string]any
    Environment string
    Timestamp   time.Time
}

type Decision struct {
    Allowed    bool
    Reason     string
    Capability string
}
```

## Evaluator Logic

### Evaluation Steps

1. **Load AgentPolicy** for `request.Agent` → not found → Deny("unknown agent")
2. **Check Restrictions** → resource matches a restriction pattern → Deny("restricted")
3. **Check Conditions** (global to the agent):
   - Time window: is `request.Timestamp` within allowed hours (UTC)?
   - Environment: is `request.Environment` in the allowed list? (empty list = allow all)
   - Rate limit: count recent calls in audit store within window → over limit → Deny("rate limit exceeded")
   - Any condition fails → Deny("condition: \<which\>")
4. **Match Capabilities** → find capabilities where `cap.Resource == request.Resource` → none → Deny("no capability for resource")
5. **Evaluate Constraints** (per matched capability):
   - String values: glob match via `filepath.Match` (e.g., `project: "ENG-*"`)
   - Slice values: list membership check (e.g., `fields: ["summary", "status"]`)
   - Numeric values: range comparison
   - All constraints pass → Allow(capability.Name)
   - No capability fully matches → Deny("constraint mismatch: \<detail\>")
6. **Log decision** to audit store

### Key Rules

- Restrictions are checked before capabilities — they are hard blocks, no capability can override them.
- Restriction matching: each restriction string is matched against the resource using prefix match (e.g., `"no_external_http"` blocks any resource starting with `"http."` or `"external_http."`). A restriction-to-resource mapping is defined in a `restriction_rules` map within the evaluator, mapping known restriction names to resource patterns. Unknown restrictions are logged as warnings but do not block.
- Conditions are agent-global — they apply to all capabilities for that agent. Per-capability conditions are a v2 item.
- First fully matching capability wins when multiple capabilities map to the same resource.

### Evaluator Interface

```go
type Evaluator struct {
    policies map[string]*AgentPolicy
    store    *audit.Store
}

func NewEvaluator(ctx context.Context, policyDir string, store *audit.Store) (*Evaluator, error)
func (e *Evaluator) Evaluate(ctx context.Context, req EvalRequest) Decision
func (e *Evaluator) Reload(ctx context.Context, policyDir string) error
```

`NewEvaluator` loads all `.capability.yaml` files from the policy directory. `Reload` supports hot-reloading via integration with the existing `internal/watcher`.

## Integration Points

### Config Addition

In `internal/config/config.go`, one new field:

```go
CapabilityPolicyDir string `mapstructure:"capability_policy_dir"`
```

Default: `~/.defenseclaw/capabilities/`

### CLI Root Wiring

In `internal/cli/root.go` `PersistentPreRunE`, after audit store initialization:

```go
capEvaluator, err := capability.NewEvaluator(cfg.CapabilityPolicyDir, auditStore)
```

### Daemon Integration

The daemon receives hook events from the agent framework. Before passing a tool call to the existing admission gate, it calls `capEvaluator.Evaluate()`. Deny decisions short-circuit the pipeline.

### New CLI Commands

Under `defenseclaw capability`:

| Command | Purpose |
|---------|---------|
| `capability list` | Show all loaded agent policies |
| `capability show <agent>` | Display agent's capabilities, restrictions, conditions |
| `capability evaluate <agent> <resource> [--param key=val]` | Dry-run an evaluation |
| `capability validate <path>` | Validate a `.capability.yaml` file |

These follow the same patterns as the existing `policy validate/show/evaluate` commands in `internal/cli/policy.go`.

### Audit Store Schema

Two new tables in the existing SQLite database:

```sql
CREATE TABLE IF NOT EXISTS capability_decisions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    agent       TEXT    NOT NULL,
    resource    TEXT    NOT NULL,
    params_json TEXT,
    allowed     INTEGER NOT NULL,
    reason      TEXT    NOT NULL,
    capability  TEXT
);

CREATE TABLE IF NOT EXISTS capability_calls (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    agent     TEXT NOT NULL,
    resource  TEXT NOT NULL,
    timestamp TEXT NOT NULL
);
```

`capability_decisions` stores all evaluation outcomes for audit trail. `capability_calls` tracks call timestamps for rate limiting (queried by the evaluator, pruned periodically).

### Audit Logger Integration

The existing audit logger (`internal/audit/logger.go`) forwards capability decisions to Splunk HEC and OTel as a new event type `capability_decision`, using the same patterns as scan results.

### TUI Integration

A new "Agents" tab in the TUI shows loaded agent policies and recent capability decisions. Follows the existing bubbletea patterns in `internal/tui/`.

## Testing Strategy

### Unit Tests (`test/unit/`)

Table-driven tests with `t.Run()` subtests, following existing conventions.

**`capability_test.go`** — Core evaluator:
- Load valid/invalid manifest files
- Match capabilities by resource name
- Constraint matching: glob patterns, list membership, exact match
- Restriction blocking overrides capabilities
- Unknown agent → deny
- No matching capability → deny
- Multiple capabilities for same resource → first full match wins

**`capability_conditions_test.go`** — Condition evaluation:
- Time window: inside, outside, edge cases (midnight crossing)
- Environment: allowed, disallowed, empty list (allow all)
- Rate limit: under, at, over limit
- Combined conditions: all must pass

**`capability_store_test.go`** — Audit store integration:
- Decision logging round-trip (insert + query)
- Rate limit counting within window
- Rate limit window expiry

### Integration Tests (`test/e2e/`)

**`capability_cli_test.go`**:
- `capability validate` — valid file passes, invalid shows errors
- `capability evaluate` — dry-run returns expected allow/deny with reason
- `capability list/show` — displays loaded policies correctly

### Test Fixtures (`test/fixtures/capabilities/`)

- `support-bot.capability.yaml` — constrained Jira + Slack access
- `admin-agent.capability.yaml` — broad access with rate limits
- `readonly-agent.capability.yaml` — read-only across services
- `invalid-missing-agent.capability.yaml` — validation error case
- `invalid-bad-constraint.capability.yaml` — malformed constraints

### Out of Scope for Testing

- OPA/Rego (not involved in this feature)
- OpenShell sandbox (capability decisions are upstream of sandbox)
- Splunk/OTel forwarding (covered by existing audit logger tests)

## Future Iterations (Out of Scope for v1)

- **Per-capability conditions** — time/env/rate at the capability level, not just agent-global
- **Sequence detection** — forbidden/required call chain enforcement
- **Risk scoring** — assign risk to actions, auto-block high-risk combinations
- **Downscoping** — modify requests instead of denying (e.g., `export_all → export(limit=10)`)
- **Escalation** — pause denied calls for human/supervisor approval
- **Capability tokens** — short-lived, task-scoped tokens issued per session
- **MCP Proxy mode** — intercept MCP JSON-RPC traffic directly for tighter enforcement
- **Dynamic tool injection** — `agent.tools = policy_engine.get_allowed_tools(context)` pattern

## Files to Create/Modify

### New Files
- `internal/capability/types.go` — Core types (AgentPolicy, Capability, Conditions, EvalRequest, Decision)
- `internal/capability/evaluator.go` — Evaluator struct, NewEvaluator, Evaluate, Reload
- `internal/capability/constraints.go` — Constraint matching logic (glob, list, exact, range)
- `internal/capability/loader.go` — YAML manifest loading and validation
- `internal/cli/capability.go` — CLI commands (list, show, evaluate, validate)
- `internal/tui/agents.go` — TUI "Agents" tab
- `test/unit/capability_test.go` — Evaluator unit tests
- `test/unit/capability_conditions_test.go` — Condition evaluation tests
- `test/unit/capability_store_test.go` — Audit store integration tests
- `test/e2e/capability_cli_test.go` — CLI integration tests
- `test/fixtures/capabilities/*.capability.yaml` — Test fixtures (5 files)

### Modified Files
- `internal/config/config.go` — Add `CapabilityPolicyDir` field
- `internal/config/defaults.go` — Add default path for capability policy dir
- `internal/audit/store.go` — Add `capability_decisions` and `capability_calls` tables + query methods
- `internal/cli/root.go` — Initialize capability evaluator in PersistentPreRunE
- `internal/daemon/daemon.go` — Call evaluator before admission gate
- `internal/tui/app.go` — Add "Agents" tab
