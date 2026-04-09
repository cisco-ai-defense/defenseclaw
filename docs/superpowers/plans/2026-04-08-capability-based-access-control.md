# Capability-Based Access Control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add capability-based access control so agents get constrained capabilities enforced at runtime, not raw tool access.

**Architecture:** New `internal/capability` package with types, YAML loader, constraint matcher, and evaluator. Integrates with existing audit store (two new tables), daemon/sidecar (pre-scan gate), CLI (new `capability` subcommand), and TUI (new "Agents" tab).

**Tech Stack:** Go 1.25, `gopkg.in/yaml.v3` (already in go.mod), `modernc.org/sqlite` (existing), Cobra (CLI), Bubbletea (TUI)

---

### Task 1: Create Branch and Test Fixtures

**Files:**
- Create: `test/fixtures/capabilities/support-bot.capability.yaml`
- Create: `test/fixtures/capabilities/admin-agent.capability.yaml`
- Create: `test/fixtures/capabilities/readonly-agent.capability.yaml`
- Create: `test/fixtures/capabilities/invalid-missing-agent.capability.yaml`
- Create: `test/fixtures/capabilities/invalid-bad-constraint.capability.yaml`

- [ ] **Step 1: Create feature branch**

```bash
cd /Users/nghodki/workspace/defenseclaw
git checkout -b feat/capability-access-control
```

- [ ] **Step 2: Create test fixtures directory**

```bash
mkdir -p test/fixtures/capabilities
```

- [ ] **Step 3: Create support-bot fixture**

Write `test/fixtures/capabilities/support-bot.capability.yaml`:

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

- [ ] **Step 4: Create admin-agent fixture**

Write `test/fixtures/capabilities/admin-agent.capability.yaml`:

```yaml
agent: admin-agent
description: "Administrative agent with broad access"

capabilities:
  - name: manage_jira
    resource: "jira.*"
    constraints: {}

  - name: manage_slack
    resource: "slack.*"
    constraints: {}

  - name: manage_confluence
    resource: "confluence.*"
    constraints: {}

restrictions: []

conditions:
  rate_limit:
    max_calls: 500
    window_seconds: 3600
```

- [ ] **Step 5: Create readonly-agent fixture**

Write `test/fixtures/capabilities/readonly-agent.capability.yaml`:

```yaml
agent: readonly-agent
description: "Read-only agent for monitoring"

capabilities:
  - name: read_jira
    resource: "jira.get_issue"
    constraints: {}

  - name: read_confluence
    resource: "confluence.get_page"
    constraints: {}

restrictions:
  - "no_write"
  - "no_delete"
  - "no_external_http"

conditions:
  environments: ["production", "staging", "dev"]
```

- [ ] **Step 6: Create invalid-missing-agent fixture**

Write `test/fixtures/capabilities/invalid-missing-agent.capability.yaml`:

```yaml
description: "Missing agent field"

capabilities:
  - name: read_jira
    resource: "jira.get_issue"
    constraints: {}
```

- [ ] **Step 7: Create invalid-bad-constraint fixture**

Write `test/fixtures/capabilities/invalid-bad-constraint.capability.yaml`:

```yaml
agent: bad-agent
description: "Bad constraint types"

capabilities:
  - name: bad_capability
    resource: ""
    constraints:
      field: 123
```

- [ ] **Step 8: Commit fixtures**

```bash
git add test/fixtures/capabilities/
git commit -m "feat(capability): add test fixtures for capability manifests"
```

---

### Task 2: Core Types

**Files:**
- Create: `internal/capability/types.go`

- [ ] **Step 1: Write the types file**

Write `internal/capability/types.go`:

```go
// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package capability

import "time"

// AgentPolicy defines the capabilities, restrictions, and conditions for a
// single agent identity. Loaded from a .capability.yaml manifest file.
type AgentPolicy struct {
	Agent        string       `yaml:"agent"`
	Description  string       `yaml:"description"`
	Capabilities []Capability `yaml:"capabilities"`
	Restrictions []string     `yaml:"restrictions"`
	Conditions   Conditions   `yaml:"conditions"`
}

// Capability grants access to a specific resource under constraints.
// Resource uses "server.tool" format (e.g. "jira.get_issue").
// Constraints are matched against request parameters.
type Capability struct {
	Name        string         `yaml:"name"`
	Resource    string         `yaml:"resource"`
	Constraints map[string]any `yaml:"constraints"`
}

// Conditions are global to an agent — they apply to all capabilities.
type Conditions struct {
	TimeWindow   string   `yaml:"time_window"`
	Environments []string `yaml:"environments"`
	RateLimit    *Rate    `yaml:"rate_limit"`
}

// Rate defines a sliding-window rate limit.
type Rate struct {
	MaxCalls      int `yaml:"max_calls"`
	WindowSeconds int `yaml:"window_seconds"`
}

// EvalRequest is the input to the capability evaluator.
type EvalRequest struct {
	Agent       string
	Resource    string
	Params      map[string]any
	Environment string
	Timestamp   time.Time
}

// Decision is the output of the capability evaluator.
type Decision struct {
	Allowed    bool   `json:"allowed"`
	Reason     string `json:"reason"`
	Capability string `json:"capability,omitempty"`
}

// Deny creates a deny decision with the given reason.
func Deny(reason string) Decision {
	return Decision{Allowed: false, Reason: reason}
}

// Allow creates an allow decision for the given capability.
func Allow(capName string) Decision {
	return Decision{Allowed: true, Reason: "capability matched", Capability: capName}
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /Users/nghodki/workspace/defenseclaw && go build ./internal/capability/`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add internal/capability/types.go
git commit -m "feat(capability): add core types for agent policies and evaluation"
```

---

### Task 3: YAML Loader with Validation

**Files:**
- Create: `internal/capability/loader.go`
- Create: `test/unit/capability_test.go`

- [ ] **Step 1: Write the failing test for loader**

Write `test/unit/capability_test.go`:

```go
// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package unit

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/capability"
)

func TestLoadPolicy(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		wantErr bool
		agent   string
		caps    int
	}{
		{
			name:  "valid support-bot",
			file:  "support-bot.capability.yaml",
			agent: "support-bot",
			caps:  3,
		},
		{
			name:  "valid admin-agent",
			file:  "admin-agent.capability.yaml",
			agent: "admin-agent",
			caps:  3,
		},
		{
			name:  "valid readonly-agent",
			file:  "readonly-agent.capability.yaml",
			agent: "readonly-agent",
			caps:  2,
		},
		{
			name:    "invalid missing agent",
			file:    "invalid-missing-agent.capability.yaml",
			wantErr: true,
		},
		{
			name:    "invalid bad constraint",
			file:    "invalid-bad-constraint.capability.yaml",
			wantErr: true,
		},
	}

	fixtureDir := filepath.Join("..", "..", "test", "fixtures", "capabilities")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(fixtureDir, tt.file)
			pol, err := capability.LoadPolicy(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadPolicy: %v", err)
			}
			if pol.Agent != tt.agent {
				t.Errorf("agent = %q, want %q", pol.Agent, tt.agent)
			}
			if len(pol.Capabilities) != tt.caps {
				t.Errorf("capabilities = %d, want %d", len(pol.Capabilities), tt.caps)
			}
		})
	}
}

func TestLoadAllPolicies(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "test", "fixtures", "capabilities")
	policies, errs := capability.LoadAllPolicies(context.Background(), fixtureDir)

	// 3 valid, 2 invalid
	if len(policies) != 3 {
		t.Errorf("loaded %d policies, want 3", len(policies))
	}
	if len(errs) != 2 {
		t.Errorf("got %d errors, want 2", len(errs))
	}

	// Check keyed by agent name
	if _, ok := policies["support-bot"]; !ok {
		t.Error("missing support-bot policy")
	}
	if _, ok := policies["admin-agent"]; !ok {
		t.Error("missing admin-agent policy")
	}
	if _, ok := policies["readonly-agent"]; !ok {
		t.Error("missing readonly-agent policy")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -run TestLoadPolicy -v`
Expected: FAIL — `capability.LoadPolicy` undefined

- [ ] **Step 3: Write the loader implementation**

Write `internal/capability/loader.go`:

```go
// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadPolicy reads and validates a single .capability.yaml manifest file.
func LoadPolicy(path string) (*AgentPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("capability: read %s: %w", path, err)
	}

	var pol AgentPolicy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return nil, fmt.Errorf("capability: parse %s: %w", path, err)
	}

	if err := validatePolicy(&pol, path); err != nil {
		return nil, err
	}

	return &pol, nil
}

// LoadAllPolicies loads all .capability.yaml files from dir.
// Returns valid policies keyed by agent name and a slice of errors for invalid files.
func LoadAllPolicies(_ context.Context, dir string) (map[string]*AgentPolicy, []error) {
	policies := make(map[string]*AgentPolicy)
	var errs []error

	entries, err := os.ReadDir(dir)
	if err != nil {
		return policies, []error{fmt.Errorf("capability: read dir %s: %w", dir, err)}
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".capability.yaml") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		pol, err := LoadPolicy(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		policies[pol.Agent] = pol
	}

	return policies, errs
}

func validatePolicy(pol *AgentPolicy, path string) error {
	if pol.Agent == "" {
		return fmt.Errorf("capability: %s: agent field is required", path)
	}

	for i, cap := range pol.Capabilities {
		if cap.Name == "" {
			return fmt.Errorf("capability: %s: capability[%d]: name is required", path, i)
		}
		if cap.Resource == "" {
			return fmt.Errorf("capability: %s: capability[%d] %q: resource is required", path, i, cap.Name)
		}
	}

	if pol.Conditions.RateLimit != nil {
		rl := pol.Conditions.RateLimit
		if rl.MaxCalls <= 0 {
			return fmt.Errorf("capability: %s: rate_limit.max_calls must be > 0", path)
		}
		if rl.WindowSeconds <= 0 {
			return fmt.Errorf("capability: %s: rate_limit.window_seconds must be > 0", path)
		}
	}

	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -run "TestLoadPolicy|TestLoadAllPolicies" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/capability/loader.go test/unit/capability_test.go
git commit -m "feat(capability): add YAML loader with validation"
```

---

### Task 4: Constraint Matching

**Files:**
- Create: `internal/capability/constraints.go`
- Modify: `test/unit/capability_test.go`

- [ ] **Step 1: Write failing tests for constraint matching**

Append to `test/unit/capability_test.go`:

```go
func TestMatchConstraints(t *testing.T) {
	tests := []struct {
		name        string
		constraints map[string]any
		params      map[string]any
		want        bool
	}{
		{
			name:        "empty constraints match anything",
			constraints: map[string]any{},
			params:      map[string]any{"project": "ENG-123"},
			want:        true,
		},
		{
			name:        "glob match success",
			constraints: map[string]any{"project": "ENG-*"},
			params:      map[string]any{"project": "ENG-123"},
			want:        true,
		},
		{
			name:        "glob match failure",
			constraints: map[string]any{"project": "ENG-*"},
			params:      map[string]any{"project": "SALES-456"},
			want:        false,
		},
		{
			name:        "exact match success",
			constraints: map[string]any{"channel": "#support"},
			params:      map[string]any{"channel": "#support"},
			want:        true,
		},
		{
			name:        "exact match failure",
			constraints: map[string]any{"channel": "#support"},
			params:      map[string]any{"channel": "#general"},
			want:        false,
		},
		{
			name:        "list membership all present",
			constraints: map[string]any{"fields": []any{"summary", "status"}},
			params:      map[string]any{"fields": []any{"summary"}},
			want:        true,
		},
		{
			name:        "list membership not in allowed",
			constraints: map[string]any{"fields": []any{"summary", "status"}},
			params:      map[string]any{"fields": []any{"password"}},
			want:        false,
		},
		{
			name:        "missing param key is denied",
			constraints: map[string]any{"project": "ENG-*"},
			params:      map[string]any{},
			want:        false,
		},
		{
			name:        "nil params with constraints is denied",
			constraints: map[string]any{"project": "ENG-*"},
			params:      nil,
			want:        false,
		},
		{
			name:        "nil constraints match anything",
			constraints: nil,
			params:      map[string]any{"anything": "goes"},
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := capability.MatchConstraints(tt.constraints, tt.params)
			if got != tt.want {
				t.Errorf("MatchConstraints() = %v, want %v", got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -run TestMatchConstraints -v`
Expected: FAIL — `capability.MatchConstraints` undefined

- [ ] **Step 3: Write constraints implementation**

Write `internal/capability/constraints.go`:

```go
// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"fmt"
	"path/filepath"
)

// MatchConstraints checks whether params satisfy all constraints.
// Returns true if every constraint key in the map is satisfied by the
// corresponding param value.
func MatchConstraints(constraints, params map[string]any) bool {
	if len(constraints) == 0 {
		return true
	}
	if params == nil {
		return false
	}

	for key, constraint := range constraints {
		paramVal, ok := params[key]
		if !ok {
			return false
		}
		if !matchValue(constraint, paramVal) {
			return false
		}
	}
	return true
}

func matchValue(constraint, param any) bool {
	switch cv := constraint.(type) {
	case string:
		return matchString(cv, param)
	case []any:
		return matchList(cv, param)
	default:
		// Fallback: exact equality via string representation
		return fmt.Sprint(constraint) == fmt.Sprint(param)
	}
}

// matchString matches a string constraint against a param value.
// Uses filepath.Match for glob patterns.
func matchString(pattern string, param any) bool {
	paramStr, ok := param.(string)
	if !ok {
		paramStr = fmt.Sprint(param)
	}

	// Try glob match first
	matched, err := filepath.Match(pattern, paramStr)
	if err != nil {
		// Invalid pattern — fall back to exact match
		return pattern == paramStr
	}
	return matched
}

// matchList checks that every element in the param list is present in the
// constraint's allowed list.
func matchList(allowed []any, param any) bool {
	paramList, ok := toStringSlice(param)
	if !ok {
		// Single value — check if it's in the allowed list
		paramStr := fmt.Sprint(param)
		for _, a := range allowed {
			if fmt.Sprint(a) == paramStr {
				return true
			}
		}
		return false
	}

	allowedSet := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		allowedSet[fmt.Sprint(a)] = true
	}

	for _, p := range paramList {
		if !allowedSet[p] {
			return false
		}
	}
	return true
}

func toStringSlice(v any) ([]string, bool) {
	switch vv := v.(type) {
	case []any:
		result := make([]string, len(vv))
		for i, item := range vv {
			result[i] = fmt.Sprint(item)
		}
		return result, true
	case []string:
		return vv, true
	default:
		return nil, false
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -run TestMatchConstraints -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/capability/constraints.go test/unit/capability_test.go
git commit -m "feat(capability): add constraint matching (glob, list, exact)"
```

---

### Task 5: Audit Store — Capability Tables

**Files:**
- Modify: `internal/audit/store.go` (add tables + methods)
- Create: `test/unit/capability_store_test.go`

- [ ] **Step 1: Write failing test for capability store**

Write `test/unit/capability_store_test.go`:

```go
// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package unit

import (
	"testing"
	"time"
)

func TestLogCapabilityDecision(t *testing.T) {
	store := newTestStore(t)

	err := store.LogCapabilityDecision("support-bot", "jira.get_issue", `{"project":"ENG-123"}`, true, "capability matched", "read_jira_ticket")
	if err != nil {
		t.Fatalf("LogCapabilityDecision: %v", err)
	}

	err = store.LogCapabilityDecision("support-bot", "slack.post_message", `{"channel":"#general"}`, false, "constraint mismatch", "")
	if err != nil {
		t.Fatalf("LogCapabilityDecision: %v", err)
	}

	decisions, err := store.ListCapabilityDecisions(10)
	if err != nil {
		t.Fatalf("ListCapabilityDecisions: %v", err)
	}
	if len(decisions) != 2 {
		t.Fatalf("expected 2 decisions, got %d", len(decisions))
	}

	// Most recent first
	if decisions[0].Resource != "slack.post_message" {
		t.Errorf("expected most recent first, got %s", decisions[0].Resource)
	}
	if decisions[0].Allowed {
		t.Error("expected denied decision")
	}
	if decisions[1].Allowed != true {
		t.Error("expected allowed decision")
	}
}

func TestRecordCapabilityCall(t *testing.T) {
	store := newTestStore(t)

	now := time.Now().UTC()

	for i := 0; i < 5; i++ {
		err := store.RecordCapabilityCall("support-bot", "jira.get_issue", now.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("RecordCapabilityCall: %v", err)
		}
	}

	count, err := store.CountCapabilityCalls("support-bot", now.Add(-1*time.Second), now.Add(10*time.Second))
	if err != nil {
		t.Fatalf("CountCapabilityCalls: %v", err)
	}
	if count != 5 {
		t.Errorf("expected 5 calls, got %d", count)
	}

	// Different agent should have 0
	count, err = store.CountCapabilityCalls("other-agent", now.Add(-1*time.Second), now.Add(10*time.Second))
	if err != nil {
		t.Fatalf("CountCapabilityCalls: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 calls for other agent, got %d", count)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -run "TestLogCapabilityDecision|TestRecordCapabilityCall" -v`
Expected: FAIL — methods undefined

- [ ] **Step 3: Add capability tables and methods to store.go**

Add to `internal/audit/store.go` in the `Init()` method's schema string, after the `CREATE UNIQUE INDEX` for actions (line 152):

```go
	CREATE TABLE IF NOT EXISTS capability_decisions (
		id          TEXT PRIMARY KEY,
		timestamp   DATETIME NOT NULL,
		agent       TEXT NOT NULL,
		resource    TEXT NOT NULL,
		params_json TEXT,
		allowed     INTEGER NOT NULL,
		reason      TEXT NOT NULL,
		capability  TEXT
	);

	CREATE TABLE IF NOT EXISTS capability_calls (
		id        TEXT PRIMARY KEY,
		agent     TEXT NOT NULL,
		resource  TEXT NOT NULL,
		timestamp DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_cap_decisions_agent ON capability_decisions(agent);
	CREATE INDEX IF NOT EXISTS idx_cap_decisions_ts ON capability_decisions(timestamp);
	CREATE INDEX IF NOT EXISTS idx_cap_calls_agent_ts ON capability_calls(agent, timestamp);
```

Add these types and methods at the end of `internal/audit/store.go`, before `Close()`:

```go
// --- Capability Decisions ---

// CapabilityDecisionRow represents a logged capability evaluation outcome.
type CapabilityDecisionRow struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Agent      string    `json:"agent"`
	Resource   string    `json:"resource"`
	ParamsJSON string    `json:"params_json,omitempty"`
	Allowed    bool      `json:"allowed"`
	Reason     string    `json:"reason"`
	Capability string    `json:"capability,omitempty"`
}

// LogCapabilityDecision inserts a capability evaluation outcome.
func (s *Store) LogCapabilityDecision(agent, resource, paramsJSON string, allowed bool, reason, capName string) error {
	id := uuid.New().String()
	now := time.Now().UTC()
	allowedInt := 0
	if allowed {
		allowedInt = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO capability_decisions (id, timestamp, agent, resource, params_json, allowed, reason, capability)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, now, agent, resource, nullStr(paramsJSON), allowedInt, reason, nullStr(capName),
	)
	if err != nil {
		return fmt.Errorf("audit: log capability decision: %w", err)
	}
	return nil
}

// ListCapabilityDecisions returns the most recent capability decisions.
func (s *Store) ListCapabilityDecisions(limit int) ([]CapabilityDecisionRow, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id, timestamp, agent, resource, params_json, allowed, reason, capability
		 FROM capability_decisions ORDER BY timestamp DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list capability decisions: %w", err)
	}
	defer rows.Close()

	var results []CapabilityDecisionRow
	for rows.Next() {
		var r CapabilityDecisionRow
		var paramsJSON, capName sql.NullString
		var allowedInt int
		if err := rows.Scan(&r.ID, &r.Timestamp, &r.Agent, &r.Resource, &paramsJSON, &allowedInt, &r.Reason, &capName); err != nil {
			return nil, fmt.Errorf("audit: scan capability decision row: %w", err)
		}
		r.ParamsJSON = paramsJSON.String
		r.Capability = capName.String
		r.Allowed = allowedInt == 1
		results = append(results, r)
	}
	return results, rows.Err()
}

// RecordCapabilityCall records a timestamp for rate limiting.
func (s *Store) RecordCapabilityCall(agent, resource string, ts time.Time) error {
	id := uuid.New().String()
	_, err := s.db.Exec(
		`INSERT INTO capability_calls (id, agent, resource, timestamp) VALUES (?, ?, ?, ?)`,
		id, agent, resource, ts,
	)
	if err != nil {
		return fmt.Errorf("audit: record capability call: %w", err)
	}
	return nil
}

// CountCapabilityCalls counts calls by an agent within a time window.
func (s *Store) CountCapabilityCalls(agent string, from, to time.Time) (int, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM capability_calls WHERE agent = ? AND timestamp >= ? AND timestamp <= ?`,
		agent, from, to,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("audit: count capability calls: %w", err)
	}
	return count, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -run "TestLogCapabilityDecision|TestRecordCapabilityCall" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/audit/store.go test/unit/capability_store_test.go
git commit -m "feat(capability): add capability_decisions and capability_calls tables to audit store"
```

---

### Task 6: Evaluator

**Files:**
- Create: `internal/capability/evaluator.go`
- Modify: `test/unit/capability_test.go`

- [ ] **Step 1: Write failing tests for evaluator**

Append to `test/unit/capability_test.go`:

```go
func newTestEvaluator(t *testing.T) *capability.Evaluator {
	t.Helper()
	store := newTestStore(t)
	fixtureDir := filepath.Join("..", "..", "test", "fixtures", "capabilities")
	eval, err := capability.NewEvaluator(context.Background(), fixtureDir, store)
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}
	return eval
}

func TestEvaluateUnknownAgent(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:    "nonexistent",
		Resource: "jira.get_issue",
	})
	if dec.Allowed {
		t.Fatal("expected deny for unknown agent")
	}
	if dec.Reason != "unknown agent" {
		t.Errorf("reason = %q, want %q", dec.Reason, "unknown agent")
	}
}

func TestEvaluateRestricted(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "readonly-agent",
		Resource:    "jira.delete_issue",
		Environment: "production",
	})
	if dec.Allowed {
		t.Fatal("expected deny for restricted resource")
	}
}

func TestEvaluateNoCapability(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "github.create_pr",
		Environment: "production",
		Timestamp:   time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
	})
	if dec.Allowed {
		t.Fatal("expected deny for resource with no capability")
	}
	if dec.Reason != "no capability for resource" {
		t.Errorf("reason = %q", dec.Reason)
	}
}

func TestEvaluateConstraintMatch(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-123"},
		Environment: "production",
		Timestamp:   time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
	})
	if !dec.Allowed {
		t.Fatalf("expected allow, got deny: %s", dec.Reason)
	}
	if dec.Capability != "read_jira_ticket" {
		t.Errorf("capability = %q, want %q", dec.Capability, "read_jira_ticket")
	}
}

func TestEvaluateConstraintMismatch(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "SALES-456"},
		Environment: "production",
		Timestamp:   time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
	})
	if dec.Allowed {
		t.Fatal("expected deny for constraint mismatch")
	}
}

func TestEvaluateAdminWildcard(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:    "admin-agent",
		Resource: "jira.delete_issue",
		Params:   map[string]any{},
	})
	if !dec.Allowed {
		t.Fatalf("expected allow for admin wildcard, got deny: %s", dec.Reason)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -run "TestEvaluate" -v`
Expected: FAIL — `capability.Evaluator` undefined

- [ ] **Step 3: Write evaluator implementation**

Write `internal/capability/evaluator.go`:

```go
// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// restrictionRules maps known restriction names to resource prefix patterns.
// A restriction blocks any resource that matches one of its patterns.
var restrictionRules = map[string][]string{
	"no_external_http": {"http.", "external_http."},
	"no_bulk_export":   {"*.export_all", "*.bulk_export"},
	"no_write":         {"*.create_*", "*.update_*", "*.set_*", "*.add_*", "*.post_*"},
	"no_delete":        {"*.delete_*", "*.remove_*"},
}

// Evaluator evaluates capability-based access control decisions.
type Evaluator struct {
	policies  map[string]*AgentPolicy
	store     *audit.Store
	policyDir string
}

// NewEvaluator loads all capability manifests from policyDir.
func NewEvaluator(ctx context.Context, policyDir string, store *audit.Store) (*Evaluator, error) {
	policies, errs := LoadAllPolicies(ctx, policyDir)
	for _, err := range errs {
		fmt.Printf("warning: %v\n", err)
	}

	return &Evaluator{
		policies:  policies,
		store:     store,
		policyDir: policyDir,
	}, nil
}

// Evaluate runs the capability evaluation pipeline for a request.
func (e *Evaluator) Evaluate(ctx context.Context, req EvalRequest) Decision {
	if req.Timestamp.IsZero() {
		req.Timestamp = time.Now().UTC()
	}

	dec := e.evaluate(ctx, req)

	// Log decision to audit store
	if e.store != nil {
		paramsJSON := ""
		if req.Params != nil {
			if data, err := json.Marshal(req.Params); err == nil {
				paramsJSON = string(data)
			}
		}
		_ = e.store.LogCapabilityDecision(req.Agent, req.Resource, paramsJSON, dec.Allowed, dec.Reason, dec.Capability)

		// Record call for rate limiting if allowed
		if dec.Allowed {
			_ = e.store.RecordCapabilityCall(req.Agent, req.Resource, req.Timestamp)
		}
	}

	return dec
}

func (e *Evaluator) evaluate(_ context.Context, req EvalRequest) Decision {
	// Step 1: Load agent policy
	pol, ok := e.policies[req.Agent]
	if !ok {
		return Deny("unknown agent")
	}

	// Step 2: Check restrictions
	if reason := checkRestrictions(pol.Restrictions, req.Resource); reason != "" {
		return Deny("restricted: " + reason)
	}

	// Step 3: Check conditions
	if reason := e.checkConditions(pol, req); reason != "" {
		return Deny("condition: " + reason)
	}

	// Step 4+5: Match capabilities and evaluate constraints
	for _, cap := range pol.Capabilities {
		if !matchResource(cap.Resource, req.Resource) {
			continue
		}
		if MatchConstraints(cap.Constraints, req.Params) {
			return Allow(cap.Name)
		}
	}

	// No capability matched
	if hasResourceMatch(pol.Capabilities, req.Resource) {
		return Deny("constraint mismatch")
	}
	return Deny("no capability for resource")
}

// Reload reloads all capability manifests from the policy directory.
func (e *Evaluator) Reload(ctx context.Context, policyDir string) error {
	if policyDir != "" {
		e.policyDir = policyDir
	}
	policies, errs := LoadAllPolicies(ctx, e.policyDir)
	for _, err := range errs {
		fmt.Printf("warning: %v\n", err)
	}
	e.policies = policies
	return nil
}

// Policies returns the loaded agent policies (for CLI/TUI display).
func (e *Evaluator) Policies() map[string]*AgentPolicy {
	return e.policies
}

func checkRestrictions(restrictions []string, resource string) string {
	for _, r := range restrictions {
		patterns, ok := restrictionRules[r]
		if !ok {
			continue
		}
		for _, pattern := range patterns {
			matched, err := filepath.Match(pattern, resource)
			if err == nil && matched {
				return r
			}
		}
	}
	return ""
}

func (e *Evaluator) checkConditions(pol *AgentPolicy, req EvalRequest) string {
	cond := pol.Conditions

	// Time window check
	if cond.TimeWindow != "" {
		if reason := checkTimeWindow(cond.TimeWindow, req.Timestamp); reason != "" {
			return reason
		}
	}

	// Environment check
	if len(cond.Environments) > 0 && req.Environment != "" {
		found := false
		for _, env := range cond.Environments {
			if env == req.Environment {
				found = true
				break
			}
		}
		if !found {
			return fmt.Sprintf("environment %q not allowed", req.Environment)
		}
	}

	// Rate limit check
	if cond.RateLimit != nil && e.store != nil {
		rl := cond.RateLimit
		windowStart := req.Timestamp.Add(-time.Duration(rl.WindowSeconds) * time.Second)
		count, err := e.store.CountCapabilityCalls(req.Agent, windowStart, req.Timestamp)
		if err != nil {
			return "rate limit check failed"
		}
		if count >= rl.MaxCalls {
			return "rate limit exceeded"
		}
	}

	return ""
}

func checkTimeWindow(window string, ts time.Time) string {
	parts := strings.SplitN(window, "-", 2)
	if len(parts) != 2 {
		return ""
	}

	startStr := strings.TrimSpace(parts[0])
	endStr := strings.TrimSpace(parts[1])

	start, err := time.Parse("15:04", startStr)
	if err != nil {
		return ""
	}
	end, err := time.Parse("15:04", endStr)
	if err != nil {
		return ""
	}

	current := time.Date(0, 1, 1, ts.Hour(), ts.Minute(), 0, 0, time.UTC)
	startTime := time.Date(0, 1, 1, start.Hour(), start.Minute(), 0, 0, time.UTC)
	endTime := time.Date(0, 1, 1, end.Hour(), end.Minute(), 0, 0, time.UTC)

	if startTime.Before(endTime) {
		// Normal window: 09:00-18:00
		if current.Before(startTime) || !current.Before(endTime) {
			return fmt.Sprintf("outside time window %s", window)
		}
	} else {
		// Midnight-crossing window: 22:00-06:00
		if current.Before(startTime) && !current.Before(endTime) {
			return fmt.Sprintf("outside time window %s", window)
		}
	}

	return ""
}

// matchResource checks if a capability's resource pattern matches a request resource.
// Supports exact match and glob patterns (e.g., "jira.*" matches "jira.get_issue").
func matchResource(pattern, resource string) bool {
	if pattern == resource {
		return true
	}
	matched, err := filepath.Match(pattern, resource)
	if err != nil {
		return false
	}
	return matched
}

func hasResourceMatch(caps []Capability, resource string) bool {
	for _, cap := range caps {
		if matchResource(cap.Resource, resource) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -run "TestEvaluate" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/capability/evaluator.go test/unit/capability_test.go
git commit -m "feat(capability): add evaluator with restriction, condition, and constraint checks"
```

---

### Task 7: Condition Tests

**Files:**
- Create: `test/unit/capability_conditions_test.go`

- [ ] **Step 1: Write condition tests**

Write `test/unit/capability_conditions_test.go`:

```go
// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package unit

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/capability"
)

func TestTimeWindowInside(t *testing.T) {
	eval := newTestEvaluator(t)
	// support-bot has time_window: "09:00-18:00"
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-1"},
		Environment: "production",
		Timestamp:   time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
	})
	if !dec.Allowed {
		t.Fatalf("expected allow inside time window, got deny: %s", dec.Reason)
	}
}

func TestTimeWindowOutside(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-1"},
		Environment: "production",
		Timestamp:   time.Date(2026, 4, 8, 3, 0, 0, 0, time.UTC),
	})
	if dec.Allowed {
		t.Fatal("expected deny outside time window")
	}
}

func TestTimeWindowEdgeStart(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-1"},
		Environment: "production",
		Timestamp:   time.Date(2026, 4, 8, 9, 0, 0, 0, time.UTC),
	})
	if !dec.Allowed {
		t.Fatalf("expected allow at window start, got deny: %s", dec.Reason)
	}
}

func TestTimeWindowEdgeEnd(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-1"},
		Environment: "production",
		Timestamp:   time.Date(2026, 4, 8, 18, 0, 0, 0, time.UTC),
	})
	if dec.Allowed {
		t.Fatal("expected deny at window end (exclusive)")
	}
}

func TestEnvironmentAllowed(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-1"},
		Environment: "staging",
		Timestamp:   time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
	})
	if !dec.Allowed {
		t.Fatalf("expected allow for staging, got deny: %s", dec.Reason)
	}
}

func TestEnvironmentDisallowed(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-1"},
		Environment: "dev",
		Timestamp:   time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
	})
	if dec.Allowed {
		t.Fatal("expected deny for dev environment")
	}
}

func TestEnvironmentEmptyAllowsAll(t *testing.T) {
	eval := newTestEvaluator(t)
	// admin-agent has no environments restriction
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "admin-agent",
		Resource:    "jira.get_issue",
		Params:      map[string]any{},
		Environment: "any-env",
	})
	if !dec.Allowed {
		t.Fatalf("expected allow with empty environments, got deny: %s", dec.Reason)
	}
}

func TestRateLimitUnder(t *testing.T) {
	eval := newTestEvaluator(t)
	// support-bot has rate_limit: max_calls=100, window_seconds=3600
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-1"},
		Environment: "production",
		Timestamp:   time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
	})
	if !dec.Allowed {
		t.Fatalf("expected allow under rate limit, got deny: %s", dec.Reason)
	}
}

func TestCombinedConditionsFail(t *testing.T) {
	eval := newTestEvaluator(t)
	// Wrong environment AND outside time window
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-1"},
		Environment: "dev",
		Timestamp:   time.Date(2026, 4, 8, 3, 0, 0, 0, time.UTC),
	})
	if dec.Allowed {
		t.Fatal("expected deny when multiple conditions fail")
	}
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -run "TestTimeWindow|TestEnvironment|TestRateLimit|TestCombined" -v`
Expected: PASS (evaluator already implements all conditions)

- [ ] **Step 3: Commit**

```bash
git add test/unit/capability_conditions_test.go
git commit -m "test(capability): add condition evaluation tests (time, env, rate, combined)"
```

---

### Task 8: Config Integration

**Files:**
- Modify: `internal/config/config.go:42-63` — add field to Config struct
- Modify: `internal/config/defaults.go:79-179` — add default in DefaultConfig

- [ ] **Step 1: Add CapabilityPolicyDir to Config struct**

In `internal/config/config.go`, add the field after `PolicyDir` (line 47):

```go
CapabilityPolicyDir string `mapstructure:"capability_policy_dir" yaml:"capability_policy_dir"`
```

- [ ] **Step 2: Add default in setDefaults()**

In `internal/config/config.go`, in the `setDefaults` function, after `viper.SetDefault("policy_dir", ...)` (line 557):

```go
viper.SetDefault("capability_policy_dir", filepath.Join(dataDir, "capabilities"))
```

- [ ] **Step 3: Add to DefaultConfig()**

In `internal/config/defaults.go`, in `DefaultConfig()`, after `PolicyDir` (line 87):

```go
CapabilityPolicyDir: filepath.Join(dataDir, "capabilities"),
```

- [ ] **Step 4: Verify it compiles**

Run: `cd /Users/nghodki/workspace/defenseclaw && go build ./...`
Expected: no errors

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/defaults.go
git commit -m "feat(capability): add capability_policy_dir config field"
```

---

### Task 9: CLI Commands

**Files:**
- Create: `internal/cli/capability.go`

- [ ] **Step 1: Write the CLI commands**

Write `internal/cli/capability.go`:

```go
// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/capability"
)

func init() {
	rootCmd.AddCommand(capabilityCmd)
	capabilityCmd.AddCommand(capListCmd)
	capabilityCmd.AddCommand(capShowCmd)
	capabilityCmd.AddCommand(capEvaluateCmd)
	capabilityCmd.AddCommand(capValidateCmd)

	capEvaluateCmd.Flags().StringSlice("param", nil, "Parameters as key=value pairs")
	capEvaluateCmd.Flags().String("env", "", "Environment label")
}

var capabilityCmd = &cobra.Command{
	Use:   "capability",
	Short: "Manage agent capability policies",
	Long:  "List, inspect, evaluate, and validate agent capability policies.",
}

// ---------------------------------------------------------------------------
// capability list
// ---------------------------------------------------------------------------

var capListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all loaded agent capability policies",
	RunE: func(_ *cobra.Command, _ []string) error {
		dir := cfg.CapabilityPolicyDir
		policies, errs := capability.LoadAllPolicies(context.Background(), dir)

		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "warning: %v\n", e)
		}

		if len(policies) == 0 {
			fmt.Printf("No capability policies found in %s\n", dir)
			return nil
		}

		fmt.Printf("Agent Capability Policies (%s)\n", dir)
		fmt.Println(strings.Repeat("─", 60))

		for name, pol := range policies {
			fmt.Printf("  %-20s %d capabilities, %d restrictions\n",
				name, len(pol.Capabilities), len(pol.Restrictions))
		}
		return nil
	},
}

// ---------------------------------------------------------------------------
// capability show <agent>
// ---------------------------------------------------------------------------

var capShowCmd = &cobra.Command{
	Use:   "show <agent>",
	Short: "Display an agent's capabilities, restrictions, and conditions",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		dir := cfg.CapabilityPolicyDir
		policies, _ := capability.LoadAllPolicies(context.Background(), dir)

		pol, ok := policies[args[0]]
		if !ok {
			return fmt.Errorf("agent %q not found in %s", args[0], dir)
		}

		out, err := json.MarshalIndent(pol, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	},
}

// ---------------------------------------------------------------------------
// capability evaluate <agent> <resource>
// ---------------------------------------------------------------------------

var capEvaluateCmd = &cobra.Command{
	Use:   "evaluate <agent> <resource>",
	Short: "Dry-run a capability evaluation",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := cfg.CapabilityPolicyDir
		eval, err := capability.NewEvaluator(context.Background(), dir, auditStore)
		if err != nil {
			return err
		}

		params := make(map[string]any)
		paramPairs, _ := cmd.Flags().GetStringSlice("param")
		for _, pair := range paramPairs {
			k, v, ok := strings.Cut(pair, "=")
			if !ok {
				return fmt.Errorf("invalid param format %q (expected key=value)", pair)
			}
			params[k] = v
		}

		env, _ := cmd.Flags().GetString("env")

		req := capability.EvalRequest{
			Agent:       args[0],
			Resource:    args[1],
			Params:      params,
			Environment: env,
			Timestamp:   time.Now().UTC(),
		}

		dec := eval.Evaluate(context.Background(), req)

		out, _ := json.MarshalIndent(dec, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

// ---------------------------------------------------------------------------
// capability validate <path>
// ---------------------------------------------------------------------------

var capValidateCmd = &cobra.Command{
	Use:   "validate <path>",
	Short: "Validate a .capability.yaml file",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		pol, err := capability.LoadPolicy(args[0])
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
		fmt.Printf("Valid: agent=%q, %d capabilities, %d restrictions\n",
			pol.Agent, len(pol.Capabilities), len(pol.Restrictions))
		return nil
	},
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /Users/nghodki/workspace/defenseclaw && go build ./...`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add internal/cli/capability.go
git commit -m "feat(capability): add CLI commands (list, show, evaluate, validate)"
```

---

### Task 10: TUI Agents Tab

**Files:**
- Create: `internal/tui/agents.go`
- Modify: `internal/tui/app.go`

- [ ] **Step 1: Write the agents panel**

Write `internal/tui/agents.go`:

```go
// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type AgentItem struct {
	Agent        string
	Capabilities int
	Restrictions int
	Decisions    int
	LastDecision string
}

type AgentsPanel struct {
	items  []AgentItem
	cursor int
	width  int
	height int
	store  *audit.Store
}

func NewAgentsPanel(store *audit.Store) AgentsPanel {
	return AgentsPanel{store: store}
}

func (p *AgentsPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

func (p *AgentsPanel) Refresh() {
	if p.store == nil {
		return
	}

	decisions, err := p.store.ListCapabilityDecisions(100)
	if err != nil {
		return
	}

	// Aggregate by agent
	agentMap := make(map[string]*AgentItem)
	for _, d := range decisions {
		item, ok := agentMap[d.Agent]
		if !ok {
			item = &AgentItem{Agent: d.Agent}
			agentMap[d.Agent] = item
		}
		item.Decisions++
		if item.LastDecision == "" {
			if d.Allowed {
				item.LastDecision = "allowed"
			} else {
				item.LastDecision = "denied: " + d.Reason
			}
		}
	}

	p.items = make([]AgentItem, 0, len(agentMap))
	for _, item := range agentMap {
		p.items = append(p.items, *item)
	}
	sort.Slice(p.items, func(i, j int) bool {
		return p.items[i].Agent < p.items[j].Agent
	})
}

func (p *AgentsPanel) Count() int {
	return len(p.items)
}

func (p *AgentsPanel) CursorUp() {
	if p.cursor > 0 {
		p.cursor--
	}
}

func (p *AgentsPanel) CursorDown() {
	if p.cursor < len(p.items)-1 {
		p.cursor++
	}
}

func (p *AgentsPanel) Selected() *AgentItem {
	if p.cursor >= 0 && p.cursor < len(p.items) {
		return &p.items[p.cursor]
	}
	return nil
}

func (p AgentsPanel) View() string {
	if len(p.items) == 0 {
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			Render("  No capability decisions recorded yet.\n  Add .capability.yaml files to ~/.defenseclaw/capabilities/")
	}

	var b strings.Builder
	header := fmt.Sprintf("  %-20s %-12s %s", "AGENT", "DECISIONS", "LAST DECISION")
	b.WriteString(HeaderStyle.Render(header))
	b.WriteString("\n")

	for i, item := range p.items {
		line := fmt.Sprintf("  %-20s %-12d %s",
			item.Agent, item.Decisions, item.LastDecision)

		if i == p.cursor {
			b.WriteString(SelectedStyle.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}

	return b.String()
}
```

- [ ] **Step 2: Update app.go to add Agents tab**

In `internal/tui/app.go`, update the tab constants (lines 30-38):

Replace:
```go
const (
	tabAlerts = iota
	tabSkills
	tabMCPs
	tabCount
)

const refreshInterval = 5 * time.Second

var tabNames = [tabCount]string{"Alerts", "Skills", "MCP Servers"}
```

With:
```go
const (
	tabAlerts = iota
	tabSkills
	tabMCPs
	tabAgents
	tabCount
)

const refreshInterval = 5 * time.Second

var tabNames = [tabCount]string{"Alerts", "Skills", "MCP Servers", "Agents"}
```

In the `Model` struct (lines 43-57), add `agents AgentsPanel` after `mcps`:

Replace:
```go
type Model struct {
	activeTab int
	width     int
	height    int

	alerts    AlertsPanel
	skills    SkillsPanel
	mcps      MCPsPanel
	detail    DetailModal
	statusBar StatusBar

	store           *audit.Store
	openshellBinary string
	anchorName      string
}
```

With:
```go
type Model struct {
	activeTab int
	width     int
	height    int

	alerts    AlertsPanel
	skills    SkillsPanel
	mcps      MCPsPanel
	agents    AgentsPanel
	detail    DetailModal
	statusBar StatusBar

	store           *audit.Store
	openshellBinary string
	anchorName      string
}
```

In the `New` function (line 59), add `agents` initialization:

Replace:
```go
func New(store *audit.Store, openshellBinary, anchorName string) Model {
	m := Model{
		alerts:          NewAlertsPanel(store),
		skills:          NewSkillsPanel(store),
		mcps:            NewMCPsPanel(store),
		detail:          NewDetailModal(),
		statusBar:       NewStatusBar(),
		store:           store,
		openshellBinary: openshellBinary,
		anchorName:      anchorName,
	}
	return m
}
```

With:
```go
func New(store *audit.Store, openshellBinary, anchorName string) Model {
	m := Model{
		alerts:          NewAlertsPanel(store),
		skills:          NewSkillsPanel(store),
		mcps:            NewMCPsPanel(store),
		agents:          NewAgentsPanel(store),
		detail:          NewDetailModal(),
		statusBar:       NewStatusBar(),
		store:           store,
		openshellBinary: openshellBinary,
		anchorName:      anchorName,
	}
	return m
}
```

In the `Update` method's `WindowSizeMsg` handler (lines 92-99), add agents sizing:

After `m.mcps.SetSize(m.width, panelH)`, add:
```go
m.agents.SetSize(m.width, panelH)
```

In the `View` method's switch (lines 176-183), add the agents case:

After the `tabMCPs` case, add:
```go
	case tabAgents:
		b.WriteString(m.agents.View())
```

In the `refresh` method (lines 198-211), add agents refresh:

After `m.mcps.Refresh()`, add:
```go
m.agents.Refresh()
```

In the `cursorUp` method (lines 213-222), add agents case:

After `tabMCPs`, add:
```go
	case tabAgents:
		m.agents.CursorUp()
```

In the `cursorDown` method (lines 224-233), add agents case:

After `tabMCPs`, add:
```go
	case tabAgents:
		m.agents.CursorDown()
```

In the `renderTabBar` method (lines 278-306), add agents count:

After the `tabMCPs` case, add:
```go
		case tabAgents:
			count = fmt.Sprintf(" (%d)", m.agents.Count())
```

- [ ] **Step 3: Verify it compiles**

Run: `cd /Users/nghodki/workspace/defenseclaw && go build ./...`
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add internal/tui/agents.go internal/tui/app.go
git commit -m "feat(capability): add Agents tab to TUI dashboard"
```

---

### Task 11: CLI Root Wiring

**Files:**
- Modify: `internal/cli/root.go:33-38` — add capEvaluator variable
- Modify: `internal/cli/root.go:60-77` — initialize evaluator in PersistentPreRunE

- [ ] **Step 1: Add evaluator variable and initialization**

In `internal/cli/root.go`, add to the `var` block (after line 38):

```go
capEvaluator *capability.Evaluator
```

Add the import for the capability package:

```go
"github.com/defenseclaw/defenseclaw/internal/capability"
```

In `PersistentPreRunE` (after `initOTelProvider()` on line 76), add:

```go
		initCapabilityEvaluator()
```

Add the initialization function after `initSplunkForwarder()`:

```go
func initCapabilityEvaluator() {
	if cfg == nil {
		return
	}
	dir := cfg.CapabilityPolicyDir
	if dir == "" {
		return
	}
	eval, err := capability.NewEvaluator(context.Background(), dir, auditStore)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: capability evaluator init: %v\n", err)
		return
	}
	capEvaluator = eval
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /Users/nghodki/workspace/defenseclaw && go build ./...`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add internal/cli/root.go
git commit -m "feat(capability): wire evaluator into CLI root lifecycle"
```

---

### Task 12: Run Full Test Suite

**Files:** None (verification only)

- [ ] **Step 1: Run all Go tests**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./... -v -count=1`
Expected: All tests PASS, including existing tests and all new capability tests.

- [ ] **Step 2: Run Go vet**

Run: `cd /Users/nghodki/workspace/defenseclaw && go vet ./...`
Expected: No issues

- [ ] **Step 3: Run build**

Run: `cd /Users/nghodki/workspace/defenseclaw && make gateway`
Expected: Build succeeds

- [ ] **Step 4: Fix any issues found**

If any tests fail or vet reports issues, fix them and re-run.

- [ ] **Step 5: Final commit if any fixes were needed**

```bash
git add -A
git commit -m "fix(capability): address test/vet issues from full suite run"
```

---

### Summary of Files

**New files (11):**
- `internal/capability/types.go`
- `internal/capability/loader.go`
- `internal/capability/constraints.go`
- `internal/capability/evaluator.go`
- `internal/cli/capability.go`
- `internal/tui/agents.go`
- `test/unit/capability_test.go`
- `test/unit/capability_conditions_test.go`
- `test/unit/capability_store_test.go`
- `test/fixtures/capabilities/` (5 YAML fixture files)

**Modified files (5):**
- `internal/config/config.go` — `CapabilityPolicyDir` field + default
- `internal/config/defaults.go` — `CapabilityPolicyDir` in `DefaultConfig()`
- `internal/audit/store.go` — Two new tables + 4 new methods
- `internal/cli/root.go` — Evaluator initialization
- `internal/tui/app.go` — Agents tab integration

**Deferred to follow-up (not in this plan):**
- `test/e2e/capability_cli_test.go` — E2E tests require built binary; add after initial merge
- Gateway sidecar integration (`internal/gateway/`) — Wiring the evaluator into the real-time tool_call event loop requires understanding the gateway WebSocket handler, which is a separate task. The CLI `capability evaluate` command provides dry-run capability in the meantime.
