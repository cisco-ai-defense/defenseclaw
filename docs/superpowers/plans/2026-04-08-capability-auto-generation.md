# Capability Auto-Generation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Auto-generate `.capability.yaml` files when skills/MCP servers pass the admission gate, with manifest introspection, scan-informed posture, and an approve workflow.

**Architecture:** The generator hooks into `runAdmission()` in the watcher after the verdict is determined. It introspects MCP manifests for per-tool granularity and skill manifests for permission-based restrictions, then writes `auto-<name>.capability.yaml` with security posture derived from scan findings. An approve CLI command renames the file to transfer ownership to the user.

**Tech Stack:** Go 1.25, `gopkg.in/yaml.v3`, `encoding/json`, Cobra CLI, Bubbletea TUI, SQLite audit store

---

## File Structure

### New Files
| File | Responsibility |
|------|---------------|
| `internal/capability/introspect.go` | Parse MCP JSON manifests and skill YAML manifests to extract tool/permission metadata |
| `internal/capability/generator.go` | Generate `AgentPolicy` from introspection results + scan posture; write YAML to disk |
| `test/unit/capability_introspect_test.go` | Unit tests for MCP and skill introspection |
| `test/unit/capability_generator_test.go` | Unit tests for policy generation logic |
| `test/unit/capability_approve_test.go` | Unit tests for the approve file lifecycle |
| `test/fixtures/mcps/tools-mcp.json` | MCP manifest with 3 tools (get_weather, create_alert, delete_alert) |
| `test/fixtures/mcps/no-tools-mcp.json` | MCP manifest with empty tools array |
| `test/fixtures/skills/permissioned-skill/skill.yaml` | Skill manifest with `permissions: [read-only]` |

### Modified Files
| File | Changes |
|------|---------|
| `internal/capability/types.go` | Add `Generated`, `Approved` fields to `AgentPolicy`; add `ToolInfo`, `SkillInfo`, `GenerateRequest`, `ScanResultSummary` types |
| `internal/watcher/watcher.go` | Add `capabilityDir`, `capEvaluator` fields to `InstallWatcher`; add `generateCapabilityPolicy()` method; hook into `runAdmission()` return points |
| `internal/cli/capability.go` | Add `capApproveCmd` for `capability approve <agent>` |
| `internal/tui/agents.go` | Add `Status` field to `AgentItem`; add `SetPolicies()` method; add status column with color coding |
| `internal/tui/app.go` | Add `capEvaluator` to `Model`; pass policies to `agents.SetPolicies()` in `refresh()` |

---

### Task 1: Test Fixtures

**Files:**
- Create: `test/fixtures/mcps/tools-mcp.json`
- Create: `test/fixtures/mcps/no-tools-mcp.json`
- Create: `test/fixtures/skills/permissioned-skill/skill.yaml`

- [ ] **Step 1: Create MCP fixture with 3 tools**

Create `test/fixtures/mcps/tools-mcp.json` — an MCP manifest with a mix of read-like and write/delete tools for testing posture filtering:

```json
{
  "name": "alert-service",
  "version": "1.0.0",
  "url": "https://alerts.example.com/mcp",
  "tools": [
    {
      "name": "get_weather",
      "description": "Get current weather for a location",
      "parameters": {
        "location": { "type": "string", "required": true }
      }
    },
    {
      "name": "create_alert",
      "description": "Create a new alert rule",
      "parameters": {
        "name": { "type": "string", "required": true },
        "threshold": { "type": "number", "required": true }
      }
    },
    {
      "name": "delete_alert",
      "description": "Delete an existing alert",
      "parameters": {
        "alert_id": { "type": "string", "required": true }
      }
    }
  ]
}
```

- [ ] **Step 2: Create MCP fixture with empty tools**

Create `test/fixtures/mcps/no-tools-mcp.json`:

```json
{
  "name": "empty-service",
  "version": "1.0.0",
  "url": "https://empty.example.com/mcp",
  "tools": []
}
```

- [ ] **Step 3: Create skill fixture with permissions**

Create `test/fixtures/skills/permissioned-skill/skill.yaml`:

```yaml
name: permissioned-skill
version: "1.0.0"
description: A skill with read-only permissions for testing
author: test-user

capabilities:
  - text-generation

permissions:
  - read-only
```

- [ ] **Step 4: Verify fixtures are valid JSON/YAML**

Run:
```bash
cd /Users/nghodki/workspace/defenseclaw
python3 -c "import json; json.load(open('test/fixtures/mcps/tools-mcp.json'))" && echo "tools-mcp.json OK"
python3 -c "import json; json.load(open('test/fixtures/mcps/no-tools-mcp.json'))" && echo "no-tools-mcp.json OK"
python3 -c "import yaml; yaml.safe_load(open('test/fixtures/skills/permissioned-skill/skill.yaml'))" && echo "permissioned-skill OK"
```

Expected: All three print OK.

- [ ] **Step 5: Commit**

```bash
git add test/fixtures/mcps/tools-mcp.json test/fixtures/mcps/no-tools-mcp.json test/fixtures/skills/permissioned-skill/skill.yaml
git commit -m "test: add fixtures for capability auto-generation"
```

---

### Task 2: Type Additions

**Files:**
- Modify: `internal/capability/types.go`

- [ ] **Step 1: Write the failing test**

Create `test/unit/capability_autogen_types_test.go`:

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

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/capability"
)

func TestAgentPolicyGeneratedApprovedFields(t *testing.T) {
	input := `
agent: test-agent
description: "test"
generated: true
approved: false
capabilities: []
restrictions: []
conditions: {}
`
	var pol capability.AgentPolicy
	if err := yaml.Unmarshal([]byte(input), &pol); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !pol.Generated {
		t.Error("expected Generated to be true")
	}
	if pol.Approved {
		t.Error("expected Approved to be false")
	}
}

func TestAgentPolicyOmitEmptyGeneratedApproved(t *testing.T) {
	pol := capability.AgentPolicy{
		Agent:       "plain-agent",
		Description: "no auto-gen fields",
	}
	data, err := yaml.Marshal(&pol)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)
	if containsString(s, "generated") {
		t.Error("expected generated to be omitted when false")
	}
	if containsString(s, "approved") {
		t.Error("expected approved to be omitted when false")
	}
}

func containsString(haystack, needle string) bool {
	return len(haystack) > 0 && len(needle) > 0 && indexString(haystack, needle) >= 0
}

func indexString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -run TestAgentPolicy -v`

Expected: FAIL — `AgentPolicy` has no `Generated` or `Approved` fields.

- [ ] **Step 3: Add Generated and Approved fields to AgentPolicy**

In `internal/capability/types.go`, add the two fields to `AgentPolicy` between `Description` and `Capabilities`:

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

- [ ] **Step 4: Add ToolInfo, SkillInfo, GenerateRequest, ScanResultSummary types**

Append to `internal/capability/types.go` (after the existing `Allow` function):

```go
// ToolInfo holds metadata for a single tool discovered from an MCP manifest.
type ToolInfo struct {
	Name        string
	Description string
	Parameters  map[string]any
}

// SkillInfo holds metadata extracted from a skill manifest.
type SkillInfo struct {
	Name        string
	Permissions []string
}

// ScanResultSummary is a lightweight view of scanner.ScanResult
// to avoid importing the scanner package into capability.
type ScanResultSummary struct {
	MaxSeverity   string // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", ""
	TotalFindings int
}

// GenerateRequest bundles the inputs for policy generation.
// Uses primitive types to avoid circular dependency with watcher package.
type GenerateRequest struct {
	Name       string             // skill/MCP name (from InstallEvent.Name)
	Type       string             // "skill" or "mcp"
	Tools      []ToolInfo         // from introspection (nil if introspection failed)
	SkillInfo  *SkillInfo         // from skill introspection (nil for MCP)
	ScanResult *ScanResultSummary // scan posture summary
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -run TestAgentPolicy -v`

Expected: PASS — both tests pass.

- [ ] **Step 6: Verify existing tests still pass**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -run TestCapability -v`

Expected: All existing capability tests pass (type change is backward-compatible due to `omitempty`).

- [ ] **Step 7: Commit**

```bash
git add internal/capability/types.go test/unit/capability_autogen_types_test.go
git commit -m "feat(capability): add Generated/Approved fields and auto-generation types"
```

---

### Task 3: Manifest Introspection

**Files:**
- Create: `internal/capability/introspect.go`
- Create: `test/unit/capability_introspect_test.go`

- [ ] **Step 1: Write the failing tests**

Create `test/unit/capability_introspect_test.go`:

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
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/capability"
)

func TestIntrospectMCP(t *testing.T) {
	tests := []struct {
		name      string
		file      string
		wantTools int
		wantErr   bool
	}{
		{
			name:      "3 tools",
			file:      "tools-mcp.json",
			wantTools: 3,
		},
		{
			name:      "empty tools array",
			file:      "no-tools-mcp.json",
			wantTools: 0,
		},
		{
			name:      "existing clean MCP with 1 tool",
			file:      "clean-mcp.json",
			wantTools: 1,
		},
		{
			name:    "missing file",
			file:    "nonexistent.json",
			wantErr: true,
		},
	}

	fixtureDir := filepath.Join("..", "..", "test", "fixtures", "mcps")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(fixtureDir, tt.file)
			tools, err := capability.IntrospectMCP(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(tools) != tt.wantTools {
				t.Errorf("got %d tools, want %d", len(tools), tt.wantTools)
			}
		})
	}
}

func TestIntrospectMCPToolDetails(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "test", "fixtures", "mcps")
	tools, err := capability.IntrospectMCP(filepath.Join(fixtureDir, "tools-mcp.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify first tool has expected fields
	if tools[0].Name != "get_weather" {
		t.Errorf("tools[0].Name = %q, want %q", tools[0].Name, "get_weather")
	}
	if tools[0].Description != "Get current weather for a location" {
		t.Errorf("tools[0].Description = %q, want %q", tools[0].Description, "Get current weather for a location")
	}
	if tools[0].Parameters == nil {
		t.Error("tools[0].Parameters should not be nil")
	}
}

func TestIntrospectMCPMalformedJSON(t *testing.T) {
	// Write a temp file with malformed JSON
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := writeFile(path, []byte("{not json")); err != nil {
		t.Fatal(err)
	}

	_, err := capability.IntrospectMCP(path)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestIntrospectSkill(t *testing.T) {
	tests := []struct {
		name        string
		dir         string
		wantName    string
		wantPerms   int
		wantErr     bool
	}{
		{
			name:      "skill with read-only permission",
			dir:       filepath.Join("..", "..", "test", "fixtures", "skills", "permissioned-skill"),
			wantName:  "permissioned-skill",
			wantPerms: 1,
		},
		{
			name:      "clean-skill with read-only",
			dir:       filepath.Join("..", "..", "test", "fixtures", "skills", "clean-skill"),
			wantName:  "clean-skill",
			wantPerms: 1,
		},
		{
			name:    "missing directory",
			dir:     filepath.Join("..", "..", "test", "fixtures", "skills", "nonexistent"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := capability.IntrospectSkill(tt.dir)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", info.Name, tt.wantName)
			}
			if len(info.Permissions) != tt.wantPerms {
				t.Errorf("got %d permissions, want %d", len(info.Permissions), tt.wantPerms)
			}
		})
	}
}

func TestIntrospectSkillNoPermissions(t *testing.T) {
	// Create a skill.yaml with no permissions field
	dir := t.TempDir()
	content := []byte("name: bare-skill\nversion: \"1.0.0\"\ndescription: no perms\n")
	if err := writeFile(filepath.Join(dir, "skill.yaml"), content); err != nil {
		t.Fatal(err)
	}

	info, err := capability.IntrospectSkill(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Name != "bare-skill" {
		t.Errorf("Name = %q, want %q", info.Name, "bare-skill")
	}
	if len(info.Permissions) != 0 {
		t.Errorf("got %d permissions, want 0", len(info.Permissions))
	}
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}
```

Add the missing import at the top — add `"os"` to the import block.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -run TestIntrospect -v`

Expected: FAIL — `capability.IntrospectMCP` and `capability.IntrospectSkill` don't exist.

- [ ] **Step 3: Implement introspect.go**

Create `internal/capability/introspect.go`:

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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// mcpManifest is the top-level structure of an MCP server's JSON manifest.
type mcpManifest struct {
	Name  string    `json:"name"`
	Tools []mcpTool `json:"tools"`
}

// mcpTool is a single tool entry in the MCP manifest.
type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// skillManifest is the top-level structure of a skill's YAML manifest.
type skillManifest struct {
	Name        string   `yaml:"name"`
	Permissions []string `yaml:"permissions"`
}

// IntrospectMCP parses an MCP server's JSON manifest file and returns
// per-tool metadata. Returns an empty slice (not error) for empty tools arrays.
func IntrospectMCP(path string) ([]ToolInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("introspect: read MCP manifest %s: %w", path, err)
	}

	var manifest mcpManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("introspect: parse MCP manifest %s: %w", path, err)
	}

	tools := make([]ToolInfo, 0, len(manifest.Tools))
	for _, t := range manifest.Tools {
		tools = append(tools, ToolInfo{
			Name:        t.Name,
			Description: t.Description,
			Parameters:  t.Parameters,
		})
	}

	return tools, nil
}

// IntrospectSkill parses a skill's skill.yaml manifest and returns the
// skill name and declared permissions. The path parameter is the skill
// directory (containing skill.yaml).
func IntrospectSkill(dir string) (*SkillInfo, error) {
	path := filepath.Join(dir, "skill.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("introspect: read skill manifest %s: %w", path, err)
	}

	var manifest skillManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("introspect: parse skill manifest %s: %w", path, err)
	}

	return &SkillInfo{
		Name:        manifest.Name,
		Permissions: manifest.Permissions,
	}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -run TestIntrospect -v`

Expected: PASS — all 4 test functions pass.

- [ ] **Step 5: Commit**

```bash
git add internal/capability/introspect.go test/unit/capability_introspect_test.go
git commit -m "feat(capability): add MCP and skill manifest introspection"
```

---

### Task 4: Policy Generator

**Files:**
- Create: `internal/capability/generator.go`
- Create: `test/unit/capability_generator_test.go`

- [ ] **Step 1: Write the failing tests**

Create `test/unit/capability_generator_test.go`:

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

	"github.com/defenseclaw/defenseclaw/internal/capability"
)

func TestGeneratePolicyCleanMCP(t *testing.T) {
	req := capability.GenerateRequest{
		Name: "weather-service",
		Type: "mcp",
		Tools: []capability.ToolInfo{
			{Name: "get_weather", Description: "Get weather"},
			{Name: "create_alert", Description: "Create alert"},
			{Name: "delete_alert", Description: "Delete alert"},
		},
		ScanResult: &capability.ScanResultSummary{
			MaxSeverity:   "",
			TotalFindings: 0,
		},
	}

	pol := capability.GeneratePolicy(req)

	if pol.Agent != "auto-weather-service" {
		t.Errorf("Agent = %q, want %q", pol.Agent, "auto-weather-service")
	}
	if !pol.Generated {
		t.Error("expected Generated = true")
	}
	if pol.Approved {
		t.Error("expected Approved = false")
	}
	if len(pol.Capabilities) != 3 {
		t.Errorf("got %d capabilities, want 3", len(pol.Capabilities))
	}
	if len(pol.Restrictions) != 0 {
		t.Errorf("got %d restrictions, want 0", len(pol.Restrictions))
	}
	// Permissive: no rate limit
	if pol.Conditions.RateLimit != nil {
		t.Error("expected no rate limit for clean scan")
	}

	// Verify resource naming: server.tool
	if pol.Capabilities[0].Resource != "weather-service.get_weather" {
		t.Errorf("cap[0].Resource = %q, want %q", pol.Capabilities[0].Resource, "weather-service.get_weather")
	}
}

func TestGeneratePolicyCautiousMCP(t *testing.T) {
	req := capability.GenerateRequest{
		Name: "data-service",
		Type: "mcp",
		Tools: []capability.ToolInfo{
			{Name: "get_data", Description: "Get data"},
			{Name: "create_record", Description: "Create record"},
			{Name: "delete_record", Description: "Delete record"},
		},
		ScanResult: &capability.ScanResultSummary{
			MaxSeverity:   "MEDIUM",
			TotalFindings: 2,
		},
	}

	pol := capability.GeneratePolicy(req)

	// Cautious: all tools still included
	if len(pol.Capabilities) != 3 {
		t.Errorf("got %d capabilities, want 3", len(pol.Capabilities))
	}

	// Cautious: no_bulk_export restriction
	if len(pol.Restrictions) != 1 || pol.Restrictions[0] != "no_bulk_export" {
		t.Errorf("restrictions = %v, want [no_bulk_export]", pol.Restrictions)
	}

	// Cautious: rate limit 100/3600s
	if pol.Conditions.RateLimit == nil {
		t.Fatal("expected rate limit for MEDIUM scan")
	}
	if pol.Conditions.RateLimit.MaxCalls != 100 {
		t.Errorf("MaxCalls = %d, want 100", pol.Conditions.RateLimit.MaxCalls)
	}
	if pol.Conditions.RateLimit.WindowSeconds != 3600 {
		t.Errorf("WindowSeconds = %d, want 3600", pol.Conditions.RateLimit.WindowSeconds)
	}
}

func TestGeneratePolicyRestrictiveMCP(t *testing.T) {
	req := capability.GenerateRequest{
		Name: "risky-service",
		Type: "mcp",
		Tools: []capability.ToolInfo{
			{Name: "get_status", Description: "Get status"},
			{Name: "list_items", Description: "List items"},
			{Name: "create_item", Description: "Create item"},
			{Name: "delete_item", Description: "Delete item"},
		},
		ScanResult: &capability.ScanResultSummary{
			MaxSeverity:   "HIGH",
			TotalFindings: 3,
		},
	}

	pol := capability.GeneratePolicy(req)

	// Restrictive: only read-like tools (get_status, list_items)
	if len(pol.Capabilities) != 2 {
		t.Errorf("got %d capabilities, want 2 (read-like only)", len(pol.Capabilities))
	}
	for _, cap := range pol.Capabilities {
		name := cap.Name
		if name != "get_status" && name != "list_items" {
			t.Errorf("unexpected capability %q in restrictive policy", name)
		}
	}

	// Restrictive: no_write, no_delete, no_bulk_export
	wantRestrictions := map[string]bool{
		"no_write":       true,
		"no_delete":      true,
		"no_bulk_export": true,
	}
	if len(pol.Restrictions) != 3 {
		t.Errorf("got %d restrictions, want 3", len(pol.Restrictions))
	}
	for _, r := range pol.Restrictions {
		if !wantRestrictions[r] {
			t.Errorf("unexpected restriction %q", r)
		}
	}

	// Restrictive: rate limit 50/3600s
	if pol.Conditions.RateLimit == nil {
		t.Fatal("expected rate limit for HIGH scan")
	}
	if pol.Conditions.RateLimit.MaxCalls != 50 {
		t.Errorf("MaxCalls = %d, want 50", pol.Conditions.RateLimit.MaxCalls)
	}
}

func TestGeneratePolicyFallbackWildcard(t *testing.T) {
	// No tools (introspection failed or empty)
	req := capability.GenerateRequest{
		Name: "unknown-service",
		Type: "mcp",
		Tools: nil,
		ScanResult: &capability.ScanResultSummary{
			MaxSeverity:   "",
			TotalFindings: 0,
		},
	}

	pol := capability.GeneratePolicy(req)

	if len(pol.Capabilities) != 1 {
		t.Fatalf("got %d capabilities, want 1 (wildcard)", len(pol.Capabilities))
	}
	if pol.Capabilities[0].Resource != "unknown-service.*" {
		t.Errorf("Resource = %q, want %q", pol.Capabilities[0].Resource, "unknown-service.*")
	}
}

func TestGeneratePolicySkillReadOnly(t *testing.T) {
	req := capability.GenerateRequest{
		Name: "my-skill",
		Type: "skill",
		SkillInfo: &capability.SkillInfo{
			Name:        "my-skill",
			Permissions: []string{"read-only"},
		},
		ScanResult: &capability.ScanResultSummary{
			MaxSeverity:   "",
			TotalFindings: 0,
		},
	}

	pol := capability.GeneratePolicy(req)

	// Skills get wildcard resource
	if len(pol.Capabilities) != 1 {
		t.Fatalf("got %d capabilities, want 1", len(pol.Capabilities))
	}
	if pol.Capabilities[0].Resource != "my-skill.*" {
		t.Errorf("Resource = %q, want %q", pol.Capabilities[0].Resource, "my-skill.*")
	}

	// read-only permission adds no_write and no_delete
	wantRestrictions := map[string]bool{"no_write": true, "no_delete": true}
	for _, r := range pol.Restrictions {
		if !wantRestrictions[r] {
			t.Errorf("unexpected restriction %q", r)
		}
		delete(wantRestrictions, r)
	}
	if len(wantRestrictions) > 0 {
		t.Errorf("missing restrictions: %v", wantRestrictions)
	}
}

func TestGeneratePolicySkillNoPermissions(t *testing.T) {
	req := capability.GenerateRequest{
		Name: "free-skill",
		Type: "skill",
		SkillInfo: &capability.SkillInfo{
			Name:        "free-skill",
			Permissions: nil,
		},
		ScanResult: &capability.ScanResultSummary{
			MaxSeverity:   "",
			TotalFindings: 0,
		},
	}

	pol := capability.GeneratePolicy(req)

	if len(pol.Restrictions) != 0 {
		t.Errorf("got %d restrictions, want 0 for skill with no permissions", len(pol.Restrictions))
	}
}

func TestGeneratePolicyNilScanResult(t *testing.T) {
	// ScanResult nil (e.g., allow-listed, no scan ran)
	req := capability.GenerateRequest{
		Name:       "allowed-service",
		Type:       "mcp",
		Tools:      []capability.ToolInfo{{Name: "do_thing"}},
		ScanResult: nil,
	}

	pol := capability.GeneratePolicy(req)

	// Treat nil scan as clean → permissive
	if len(pol.Restrictions) != 0 {
		t.Errorf("got %d restrictions, want 0 for nil scan result", len(pol.Restrictions))
	}
	if pol.Conditions.RateLimit != nil {
		t.Error("expected no rate limit for nil scan result")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -run TestGeneratePolicy -v`

Expected: FAIL — `capability.GeneratePolicy` doesn't exist.

- [ ] **Step 3: Implement generator.go**

Create `internal/capability/generator.go`:

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
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// readLikePrefixes are tool name prefixes considered read-only operations.
var readLikePrefixes = []string{
	"get_", "list_", "read_", "search_",
	"fetch_", "query_", "describe_", "show_",
}

// GeneratePolicy creates an AgentPolicy from introspection results and scan posture.
func GeneratePolicy(req GenerateRequest) *AgentPolicy {
	posture := classifyPosture(req.ScanResult)

	pol := &AgentPolicy{
		Agent:     "auto-" + req.Name,
		Generated: true,
		Approved:  false,
	}

	// Build capabilities from tools or wildcard fallback
	switch {
	case req.Type == "skill":
		pol.Description = fmt.Sprintf("Auto-generated from skill scan (%s)", posture)
		pol.Capabilities = []Capability{{
			Name:        req.Name,
			Resource:    req.Name + ".*",
			Constraints: map[string]any{},
		}}
	case len(req.Tools) > 0:
		pol.Description = fmt.Sprintf("Auto-generated from MCP scan (%s)", posture)
		pol.Capabilities = buildMCPCapabilities(req.Name, req.Tools, posture)
	default:
		pol.Description = fmt.Sprintf("Auto-generated from MCP scan (%s)", posture)
		pol.Capabilities = []Capability{{
			Name:        req.Name,
			Resource:    req.Name + ".*",
			Constraints: map[string]any{},
		}}
	}

	// Apply posture-based restrictions and conditions
	pol.Restrictions, pol.Conditions = postureRestrictionsAndConditions(posture)

	// Skill permission overrides: read-only adds no_write + no_delete
	if req.SkillInfo != nil {
		for _, perm := range req.SkillInfo.Permissions {
			if perm == "read-only" {
				pol.Restrictions = addUniqueStrings(pol.Restrictions, "no_write", "no_delete")
			}
		}
	}

	return pol
}

// WritePolicy marshals the policy to YAML and writes it to the given directory.
// Returns the full path of the written file.
func WritePolicy(pol *AgentPolicy, dir string) (string, error) {
	data, err := yaml.Marshal(pol)
	if err != nil {
		return "", fmt.Errorf("capability: marshal policy: %w", err)
	}

	filename := pol.Agent + ".capability.yaml"
	path := filepath.Join(dir, filename)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("capability: create dir %s: %w", dir, err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("capability: write %s: %w", path, err)
	}

	return path, nil
}

// ApprovePolicy reads auto-<agent>.capability.yaml, sets approved=true,
// writes <agent>.capability.yaml, and removes the auto file.
func ApprovePolicy(dir, agent string) (*AgentPolicy, error) {
	autoFile := filepath.Join(dir, "auto-"+agent+".capability.yaml")
	manualFile := filepath.Join(dir, agent+".capability.yaml")

	// Check manual file doesn't already exist
	if _, err := os.Stat(manualFile); err == nil {
		return nil, fmt.Errorf("capability: manual policy %s already exists — edit it directly", manualFile)
	}

	pol, err := LoadPolicy(autoFile)
	if err != nil {
		return nil, fmt.Errorf("capability: no pending auto-generated policy for %q", agent)
	}

	pol.Agent = agent
	pol.Approved = true

	data, yamlErr := yaml.Marshal(pol)
	if yamlErr != nil {
		return nil, fmt.Errorf("capability: marshal approved policy: %w", yamlErr)
	}

	if err := os.WriteFile(manualFile, data, 0o644); err != nil {
		return nil, fmt.Errorf("capability: write %s: %w", manualFile, err)
	}

	if err := os.Remove(autoFile); err != nil {
		return nil, fmt.Errorf("capability: remove auto file %s: %w", autoFile, err)
	}

	return pol, nil
}

type posture string

const (
	posturePermissive  posture = "permissive"
	postureCautious    posture = "cautious"
	postureRestrictive posture = "restrictive"
)

func classifyPosture(scan *ScanResultSummary) posture {
	if scan == nil || scan.TotalFindings == 0 {
		return posturePermissive
	}
	switch scan.MaxSeverity {
	case "HIGH", "CRITICAL":
		return postureRestrictive
	case "MEDIUM", "LOW":
		return postureCautious
	default:
		return posturePermissive
	}
}

func buildMCPCapabilities(serverName string, tools []ToolInfo, p posture) []Capability {
	caps := make([]Capability, 0, len(tools))
	for _, tool := range tools {
		if p == postureRestrictive && !isReadLike(tool.Name) {
			continue
		}
		caps = append(caps, Capability{
			Name:        tool.Name,
			Resource:    serverName + "." + tool.Name,
			Constraints: map[string]any{},
		})
	}
	return caps
}

func isReadLike(toolName string) bool {
	for _, prefix := range readLikePrefixes {
		if strings.HasPrefix(toolName, prefix) {
			return true
		}
	}
	return false
}

func postureRestrictionsAndConditions(p posture) ([]string, Conditions) {
	switch p {
	case postureCautious:
		return []string{"no_bulk_export"}, Conditions{
			RateLimit: &Rate{MaxCalls: 100, WindowSeconds: 3600},
		}
	case postureRestrictive:
		return []string{"no_write", "no_delete", "no_bulk_export"}, Conditions{
			RateLimit: &Rate{MaxCalls: 50, WindowSeconds: 3600},
		}
	default:
		return nil, Conditions{}
	}
}

func addUniqueStrings(slice []string, vals ...string) []string {
	existing := make(map[string]bool, len(slice))
	for _, s := range slice {
		existing[s] = true
	}
	for _, v := range vals {
		if !existing[v] {
			slice = append(slice, v)
			existing[v] = true
		}
	}
	return slice
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -run TestGeneratePolicy -v`

Expected: PASS — all 7 test functions pass.

- [ ] **Step 5: Commit**

```bash
git add internal/capability/generator.go test/unit/capability_generator_test.go
git commit -m "feat(capability): add scan-informed policy generator"
```

---

### Task 5: Approve Workflow Tests

**Files:**
- Create: `test/unit/capability_approve_test.go`

- [ ] **Step 1: Write the approve tests**

Create `test/unit/capability_approve_test.go`:

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
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/capability"
)

func TestApprovePolicySuccess(t *testing.T) {
	dir := t.TempDir()

	// Generate a policy and write it
	pol := capability.GeneratePolicy(capability.GenerateRequest{
		Name: "test-service",
		Type: "mcp",
		Tools: []capability.ToolInfo{
			{Name: "get_data", Description: "Get data"},
		},
		ScanResult: &capability.ScanResultSummary{TotalFindings: 0},
	})
	if _, err := capability.WritePolicy(pol, dir); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Verify auto file exists
	autoPath := filepath.Join(dir, "auto-test-service.capability.yaml")
	if _, err := os.Stat(autoPath); err != nil {
		t.Fatalf("auto file should exist: %v", err)
	}

	// Approve
	approved, err := capability.ApprovePolicy(dir, "test-service")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Verify approved policy
	if !approved.Approved {
		t.Error("expected Approved = true")
	}
	if approved.Agent != "test-service" {
		t.Errorf("Agent = %q, want %q", approved.Agent, "test-service")
	}

	// Verify auto file removed
	if _, err := os.Stat(autoPath); !os.IsNotExist(err) {
		t.Error("auto file should have been removed")
	}

	// Verify manual file exists
	manualPath := filepath.Join(dir, "test-service.capability.yaml")
	if _, err := os.Stat(manualPath); err != nil {
		t.Errorf("manual file should exist: %v", err)
	}
}

func TestApprovePolicyNoAutoFile(t *testing.T) {
	dir := t.TempDir()

	_, err := capability.ApprovePolicy(dir, "nonexistent")
	if err == nil {
		t.Fatal("expected error when no auto file exists")
	}
}

func TestApprovePolicyManualExists(t *testing.T) {
	dir := t.TempDir()

	// Write both auto and manual files
	pol := capability.GeneratePolicy(capability.GenerateRequest{
		Name: "dual-service",
		Type: "mcp",
		Tools: []capability.ToolInfo{{Name: "get_x"}},
		ScanResult: &capability.ScanResultSummary{TotalFindings: 0},
	})
	if _, err := capability.WritePolicy(pol, dir); err != nil {
		t.Fatalf("write auto: %v", err)
	}

	// Create a manual file too
	manualPath := filepath.Join(dir, "dual-service.capability.yaml")
	if err := os.WriteFile(manualPath, []byte("agent: dual-service\n"), 0o644); err != nil {
		t.Fatalf("write manual: %v", err)
	}

	_, err := capability.ApprovePolicy(dir, "dual-service")
	if err == nil {
		t.Fatal("expected error when manual file already exists")
	}
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -run TestApprovePolicy -v`

Expected: PASS — all 3 tests pass (ApprovePolicy and WritePolicy were implemented in Task 4).

- [ ] **Step 3: Commit**

```bash
git add test/unit/capability_approve_test.go
git commit -m "test(capability): add approve workflow tests"
```

---

### Task 6: CLI Approve Command

**Files:**
- Modify: `internal/cli/capability.go`

- [ ] **Step 1: Write the failing test**

This is a CLI integration test. We verify the command is registered by running it with `--help`. But first, add the `approve` subcommand.

- [ ] **Step 2: Add capApproveCmd to capability.go**

In `internal/cli/capability.go`, add `capApproveCmd` to the `init()` function's command registration:

```go
func init() {
	rootCmd.AddCommand(capabilityCmd)
	capabilityCmd.AddCommand(capListCmd)
	capabilityCmd.AddCommand(capShowCmd)
	capabilityCmd.AddCommand(capEvaluateCmd)
	capabilityCmd.AddCommand(capValidateCmd)
	capabilityCmd.AddCommand(capApproveCmd)

	capEvaluateCmd.Flags().StringSlice("param", nil, "Parameters as key=value pairs")
	capEvaluateCmd.Flags().String("env", "", "Environment label")
}
```

Then add the command definition at the bottom of the file:

```go
// ---------------------------------------------------------------------------
// capability approve <agent>
// ---------------------------------------------------------------------------

var capApproveCmd = &cobra.Command{
	Use:   "approve <agent>",
	Short: "Approve an auto-generated capability policy",
	Long: `Approve a pending auto-generated capability policy. This renames
auto-<agent>.capability.yaml to <agent>.capability.yaml and sets approved: true.`,
	Args: cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		agent := args[0]
		dir := cfg.CapabilityPolicyDir

		pol, err := capability.ApprovePolicy(dir, agent)
		if err != nil {
			return err
		}

		fmt.Printf("Approved: %s (%d capabilities, %d restrictions)\n",
			agent, len(pol.Capabilities), len(pol.Restrictions))

		// Reload evaluator if available
		if capEvaluator != nil {
			if reloadErr := capEvaluator.Reload(context.Background(), ""); reloadErr != nil {
				fmt.Fprintf(os.Stderr, "warning: reload evaluator: %v\n", reloadErr)
			}
		}

		// Log audit event
		if auditLog != nil {
			_ = auditLog.LogAction("capability_approved", agent,
				fmt.Sprintf("capabilities=%d, restrictions=%d", len(pol.Capabilities), len(pol.Restrictions)))
		}

		return nil
	},
}
```

- [ ] **Step 3: Verify the command is registered**

Run: `cd /Users/nghodki/workspace/defenseclaw && go run ./cmd/defenseclaw capability approve --help`

Expected output includes: `Approve a pending auto-generated capability policy`

- [ ] **Step 4: Verify build passes**

Run: `cd /Users/nghodki/workspace/defenseclaw && go build ./cmd/defenseclaw`

Expected: Build succeeds with no errors.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/capability.go
git commit -m "feat(cli): add capability approve command"
```

---

### Task 7: TUI Agents Panel Status Column

**Files:**
- Modify: `internal/tui/agents.go`
- Modify: `internal/tui/app.go`

- [ ] **Step 1: Add Status field and SetPolicies to agents.go**

In `internal/tui/agents.go`, add `Status` to `AgentItem` and a `policies` field + `SetPolicies` method to `AgentsPanel`:

Update the `AgentItem` struct:

```go
type AgentItem struct {
	Agent        string
	Capabilities int
	Restrictions int
	Decisions    int
	LastDecision string
	Status       string // "approved", "pending review", or "manual"
}
```

Add a `policies` field to `AgentsPanel`:

```go
type AgentsPanel struct {
	items    []AgentItem
	cursor   int
	width    int
	height   int
	store    *audit.Store
	policies map[string]*capability.AgentPolicy
}
```

Add the import for `capability` package:

```go
import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/capability"
)
```

Add the `SetPolicies` method:

```go
// SetPolicies updates the panel's view of loaded capability policies.
func (p *AgentsPanel) SetPolicies(policies map[string]*capability.AgentPolicy) {
	p.policies = policies
}
```

In the `Refresh()` method, after building `agentMap` from decisions and before converting to slice, add policy-based status resolution and merge agents from policies that have no decisions yet:

```go
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

	// Merge agents from policies that have no decisions yet
	for name := range p.policies {
		if _, ok := agentMap[name]; !ok {
			agentMap[name] = &AgentItem{Agent: name, LastDecision: "-"}
		}
	}

	// Resolve status from policies
	for name, item := range agentMap {
		pol, hasPol := p.policies[name]
		if !hasPol {
			item.Status = "manual"
			continue
		}
		item.Capabilities = len(pol.Capabilities)
		item.Restrictions = len(pol.Restrictions)
		switch {
		case pol.Generated && !pol.Approved:
			item.Status = "pending review"
		case pol.Generated && pol.Approved:
			item.Status = "approved"
		default:
			item.Status = "manual"
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
```

Update the `View()` method to add the status column with color coding:

```go
func (p AgentsPanel) View() string {
	if len(p.items) == 0 {
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			Render("  No capability decisions recorded yet.\n  Add .capability.yaml files to ~/.defenseclaw/capabilities/")
	}

	var b strings.Builder
	header := fmt.Sprintf("  %-20s %-16s %-12s %s", "AGENT", "STATUS", "DECISIONS", "LAST DECISION")
	b.WriteString(HeaderStyle.Render(header))
	b.WriteString("\n")

	for i, item := range p.items {
		statusStr := p.renderStatus(item.Status)
		line := fmt.Sprintf("  %-20s %-16s %-12d %s",
			item.Agent, statusStr, item.Decisions, item.LastDecision)

		if i == p.cursor {
			b.WriteString(SelectedStyle.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func (p AgentsPanel) renderStatus(status string) string {
	switch status {
	case "pending review":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(status)
	default:
		return status
	}
}
```

- [ ] **Step 2: Update app.go to pass policies**

In `internal/tui/app.go`, add `capEvaluator` to the `Model` struct and update `New()` and `refresh()`:

Add field to `Model`:

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
	capEvaluator    *capability.Evaluator
	openshellBinary string
	anchorName      string
}
```

Add the import:

```go
import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/capability"
)
```

Update the `New()` function signature and body:

```go
func New(store *audit.Store, capEval *capability.Evaluator, openshellBinary, anchorName string) Model {
	m := Model{
		alerts:          NewAlertsPanel(store),
		skills:          NewSkillsPanel(store),
		mcps:            NewMCPsPanel(store),
		agents:          NewAgentsPanel(store),
		detail:          NewDetailModal(),
		statusBar:       NewStatusBar(),
		store:           store,
		capEvaluator:    capEval,
		openshellBinary: openshellBinary,
		anchorName:      anchorName,
	}
	return m
}
```

Update `refresh()` to pass policies:

```go
func (m *Model) refresh() {
	if m.capEvaluator != nil {
		m.agents.SetPolicies(m.capEvaluator.Policies())
	}
	m.alerts.Refresh()
	m.skills.Refresh()
	m.mcps.Refresh()
	m.agents.Refresh()
	m.statusBar.Update(
		m.alerts.Count(),
		m.skills.Count(),
		m.skills.BlockedCount(),
		m.mcps.Count(),
		m.mcps.BlockedCount(),
	)
	m.statusBar.DetectSandbox(m.openshellBinary)
	m.statusBar.DetectFirewall(m.anchorName)
}
```

- [ ] **Step 3: Update callers of tui.New**

Find and update all callers of `tui.New()` to pass the new `capEval` parameter. Search for `tui.New(` in the codebase and add the evaluator argument (or `nil` if not available at that call site).

Run: `grep -rn "tui.New(" internal/ cmd/`

Update each call site. The main one is likely in `internal/cli/` or `cmd/defenseclaw/`. Pass `capEvaluator` (the package-level var in `cli/root.go`) or `nil`.

- [ ] **Step 4: Verify build passes**

Run: `cd /Users/nghodki/workspace/defenseclaw && go build ./cmd/defenseclaw`

Expected: Build succeeds with no errors.

- [ ] **Step 5: Run all existing tests**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./test/unit/ -v`

Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/tui/agents.go internal/tui/app.go
git commit -m "feat(tui): add status column and policy awareness to agents panel"
```

Note: Include any other files modified in Step 3 (callers of `tui.New`).

---

### Task 8: Watcher Integration

**Files:**
- Modify: `internal/watcher/watcher.go`

- [ ] **Step 1: Add capability fields to InstallWatcher**

In `internal/watcher/watcher.go`, add two new fields to the `InstallWatcher` struct (after the `otel` field on line 93):

```go
type InstallWatcher struct {
	cfg        *config.Config
	skillDirs  []string
	pluginDirs []string
	store      *audit.Store
	logger     *audit.Logger
	shell      *sandbox.OpenShell
	opa        *policy.Engine
	otel       *telemetry.Provider
	capDir     string
	capEval    *capability.Evaluator
	debounce   time.Duration
	onAdmit    OnAdmission

	mu      sync.Mutex
	pending map[string]time.Time
}
```

Add the import:

```go
"github.com/defenseclaw/defenseclaw/internal/capability"
```

- [ ] **Step 2: Add setter methods**

Add methods to set the capability fields (called from the wiring code in cli/root.go or cmd/main.go):

```go
// SetCapabilityDir sets the directory where auto-generated capability policies are written.
func (w *InstallWatcher) SetCapabilityDir(dir string) {
	w.capDir = dir
}

// SetCapabilityEvaluator sets the evaluator to reload after generating policies.
func (w *InstallWatcher) SetCapabilityEvaluator(eval *capability.Evaluator) {
	w.capEval = eval
}
```

- [ ] **Step 3: Add generateCapabilityPolicy method**

Add the method that hooks into the admission flow:

```go
// generateCapabilityPolicy creates an auto-generated capability policy for the
// given install event, if no manual or auto policy already exists.
func (w *InstallWatcher) generateCapabilityPolicy(evt InstallEvent, scanResult *scanner.ScanResult) {
	if w.capDir == "" {
		return
	}

	name := evt.Name

	// Skip if manual policy already exists
	manualPath := filepath.Join(w.capDir, name+".capability.yaml")
	if _, err := os.Stat(manualPath); err == nil {
		return
	}

	// Skip if auto policy already exists
	autoPath := filepath.Join(w.capDir, "auto-"+name+".capability.yaml")
	if _, err := os.Stat(autoPath); err == nil {
		return
	}

	// Introspect manifest
	var tools []capability.ToolInfo
	var skillInfo *capability.SkillInfo

	switch evt.Type {
	case InstallMCP:
		// Try to find and parse MCP manifest JSON
		manifestPath := filepath.Join(evt.Path, "manifest.json")
		if t, err := capability.IntrospectMCP(manifestPath); err == nil {
			tools = t
		}
	case InstallSkill:
		if si, err := capability.IntrospectSkill(evt.Path); err == nil {
			skillInfo = si
		}
	}

	// Build scan summary
	var scanSummary *capability.ScanResultSummary
	if scanResult != nil {
		scanSummary = &capability.ScanResultSummary{
			MaxSeverity:   string(scanResult.MaxSeverity()),
			TotalFindings: len(scanResult.Findings),
		}
	}

	// Generate policy
	req := capability.GenerateRequest{
		Name:       name,
		Type:       string(evt.Type),
		Tools:      tools,
		SkillInfo:  skillInfo,
		ScanResult: scanSummary,
	}
	pol := capability.GeneratePolicy(req)

	// Write to disk
	writtenPath, err := capability.WritePolicy(pol, w.capDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[watch] generate capability policy for %s: %v\n", name, err)
		return
	}

	// Log audit event
	source := "fallback"
	if len(tools) > 0 {
		source = "mcp-introspect"
	} else if skillInfo != nil {
		source = "skill-introspect"
	}
	posture := "permissive"
	if scanSummary != nil {
		switch scanSummary.MaxSeverity {
		case "HIGH", "CRITICAL":
			posture = "restrictive"
		case "MEDIUM", "LOW":
			posture = "cautious"
		}
	}
	_ = w.logger.LogAction("capability_generated", name,
		fmt.Sprintf("posture=%s, capabilities=%d, source=%s, path=%s",
			posture, len(pol.Capabilities), source, writtenPath))

	// Reload evaluator
	if w.capEval != nil {
		_ = w.capEval.Reload(context.Background(), "")
	}
}
```

- [ ] **Step 4: Hook into runAdmission return points**

In `runAdmission()`, add capability generation calls before each return that represents an allowed/clean/warning verdict. There are 5 return points to consider:

**Line 296** — OPA pre-scan `VerdictAllowed` (allow-listed, no scan ran): Call with `nil` scanResult:
```go
case "allowed":
	_ = w.logger.LogAction("install-allowed", evt.Path,
		fmt.Sprintf("type=%s reason=allow-listed", targetType))
	w.recordAdmission(ctx, "allowed", targetType)
	w.generateCapabilityPolicy(evt, nil)
	return AdmissionResult{Event: evt, Verdict: VerdictAllowed, Reason: out.Reason}
```

**Line 318** — Built-in Go `VerdictAllowed` (allow-listed, no OPA): Call with `nil` scanResult:
```go
if err == nil && allowed {
	reason := fmt.Sprintf("%s %q is on the allow list — skipping scan", targetType, evt.Name)
	_ = w.logger.LogAction("install-allowed", evt.Path,
		fmt.Sprintf("type=%s reason=allow-listed", targetType))
	w.recordAdmission(ctx, "allowed", targetType)
	w.generateCapabilityPolicy(evt, nil)
	return AdmissionResult{Event: evt, Verdict: VerdictAllowed, Reason: reason}
}
```

**Line 375** — OPA post-scan verdict (clean/warning from OPA): Call conditionally after `applyPostScanEnforcement`:
```go
w.applyPostScanEnforcement(pe, out, evt, targetType, result, s.Name())
_ = w.logger.LogScanWithVerdict(result, out.Verdict)
w.recordAdmission(ctx, out.Verdict, targetType)
if out.Verdict == "clean" || out.Verdict == "warning" {
	w.generateCapabilityPolicy(evt, result)
}
return AdmissionResult{Event: evt, Verdict: toVerdict(out.Verdict), Reason: out.Reason}
```

**Line 386** — Built-in Go `VerdictClean`: Call with `result`:
```go
if result.IsClean() {
	_ = w.logger.LogAction("install-clean", evt.Path,
		fmt.Sprintf("type=%s scanner=%s", targetType, s.Name()))
	_ = w.logger.LogScanWithVerdict(result, string(VerdictClean))
	w.recordAdmission(ctx, "scan_clean", targetType)
	w.generateCapabilityPolicy(evt, result)
	return AdmissionResult{Event: evt, Verdict: VerdictClean, Reason: "scan clean"}
}
```

**Line 428** — Built-in Go `VerdictWarning`: Call with `result`:
```go
reason := fmt.Sprintf("scan found %s findings — installed with warning", maxSev)
_ = w.logger.LogAction("install-warning", evt.Path,
	fmt.Sprintf("type=%s severity=%s scanner=%s", targetType, maxSev, s.Name()))
_ = w.logger.LogScanWithVerdict(result, string(VerdictWarning))
w.recordAdmission(ctx, "scan_warning", targetType)
w.generateCapabilityPolicy(evt, result)
return AdmissionResult{Event: evt, Verdict: VerdictWarning, Reason: reason}
```

- [ ] **Step 5: Verify build passes**

Run: `cd /Users/nghodki/workspace/defenseclaw && go build ./cmd/defenseclaw`

Expected: Build succeeds.

- [ ] **Step 6: Run all tests**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./... 2>&1 | tail -20`

Expected: All tests pass.

- [ ] **Step 7: Commit**

```bash
git add internal/watcher/watcher.go
git commit -m "feat(watcher): hook capability auto-generation into admission gate"
```

---

### Task 9: Wiring and Full Verification

**Files:**
- Possibly modify: `cmd/defenseclaw/main.go` or `internal/cli/root.go` (wherever the watcher is created)

- [ ] **Step 1: Wire capability dir and evaluator into watcher**

Find where `watcher.New()` is called and add the setter calls after creation. Search:

```bash
grep -rn "watcher.New(" cmd/ internal/cli/
```

After the watcher is created, add:
```go
installWatcher.SetCapabilityDir(cfg.CapabilityPolicyDir)
installWatcher.SetCapabilityEvaluator(capEvaluator)
```

- [ ] **Step 2: Wire capEvaluator into tui.New call**

Find where `tui.New()` is called and pass `capEvaluator`:

```bash
grep -rn "tui.New(" cmd/ internal/cli/
```

Update to: `tui.New(store, capEvaluator, openshellBinary, anchorName)`

- [ ] **Step 3: Verify full build**

Run: `cd /Users/nghodki/workspace/defenseclaw && go build ./cmd/defenseclaw`

Expected: Build succeeds.

- [ ] **Step 4: Run complete test suite**

Run: `cd /Users/nghodki/workspace/defenseclaw && go test ./... -v 2>&1 | tail -40`

Expected: All tests pass.

- [ ] **Step 5: Run go vet**

Run: `cd /Users/nghodki/workspace/defenseclaw && go vet ./...`

Expected: No issues.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(capability): wire auto-generation into watcher and TUI"
```

- [ ] **Step 7: Verify all new tests pass individually**

Run each test file in sequence to confirm isolation:

```bash
cd /Users/nghodki/workspace/defenseclaw
go test ./test/unit/ -run TestAgentPolicy -v
go test ./test/unit/ -run TestIntrospect -v
go test ./test/unit/ -run TestGeneratePolicy -v
go test ./test/unit/ -run TestApprovePolicy -v
go test ./test/unit/ -run TestCapability -v
```

Expected: All pass.
