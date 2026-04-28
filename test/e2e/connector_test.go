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

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestRegistryBuiltinConnectors(t *testing.T) {
	reg := connector.NewDefaultRegistry()

	expected := []string{"claudecode", "codex", "openclaw", "zeptoclaw"}
	names := reg.Names()
	sort.Strings(names)

	if len(names) < len(expected) {
		t.Fatalf("expected at least %d connectors, got %d: %v", len(expected), len(names), names)
	}

	for _, name := range expected {
		c, ok := reg.Get(name)
		if !ok {
			t.Errorf("built-in connector %q not found in registry", name)
			continue
		}
		if c.Name() != name {
			t.Errorf("connector.Name()=%q, want %q", c.Name(), name)
		}
		if c.Description() == "" {
			t.Errorf("connector %q has empty description", name)
		}
	}
}

func TestRegistryAvailableMetadata(t *testing.T) {
	reg := connector.NewDefaultRegistry()
	avail := reg.Available()

	if len(avail) < 4 {
		t.Fatalf("expected at least 4 connectors in Available(), got %d", len(avail))
	}

	for _, info := range avail {
		if info.Name == "" {
			t.Error("connector info has empty name")
		}
		if info.Source != "built-in" {
			t.Errorf("connector %q source=%q, want built-in", info.Name, info.Source)
		}
		if info.ToolInspectionMode == "" {
			t.Errorf("connector %q has empty tool_inspection_mode", info.Name)
		}
		if info.SubprocessPolicy == "" {
			t.Errorf("connector %q has empty subprocess_policy", info.Name)
		}
	}
}

func TestRegistryGetUnknown(t *testing.T) {
	reg := connector.NewDefaultRegistry()
	_, ok := reg.Get("nonexistent-connector")
	if ok {
		t.Error("Get() should return false for unknown connector name")
	}
}

func TestActiveConnectorStatePersistence(t *testing.T) {
	dir := t.TempDir()

	// Initially no state file.
	name := connector.LoadActiveConnector(dir)
	if name != "" {
		t.Fatalf("LoadActiveConnector on empty dir should return empty, got %q", name)
	}

	// Save state.
	if err := connector.SaveActiveConnector(dir, "claudecode"); err != nil {
		t.Fatalf("SaveActiveConnector: %v", err)
	}

	// Load state back.
	name = connector.LoadActiveConnector(dir)
	if name != "claudecode" {
		t.Fatalf("LoadActiveConnector=%q, want claudecode", name)
	}

	// Verify file contents.
	data, err := os.ReadFile(filepath.Join(dir, "active_connector.json"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var state struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if state.Name != "claudecode" {
		t.Fatalf("state file name=%q, want claudecode", state.Name)
	}

	// Clear state.
	connector.ClearActiveConnector(dir)
	name = connector.LoadActiveConnector(dir)
	if name != "" {
		t.Fatalf("after Clear, LoadActiveConnector should return empty, got %q", name)
	}
}

func TestActiveConnectorStateMalformed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "active_connector.json"), []byte("{invalid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	name := connector.LoadActiveConnector(dir)
	if name != "" {
		t.Fatalf("malformed state file should return empty, got %q", name)
	}
}

func TestConnectorVerifyCleanOnFreshDataDir(t *testing.T) {
	reg := connector.NewDefaultRegistry()
	dir := t.TempDir()
	opts := connector.SetupOpts{
		DataDir:   dir,
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	}

	// Plan E3: walk every built-in connector — not just the
	// home-independent ones. We isolate every connector's host
	// config path to a tmpdir via the *PathOverride seams so the
	// test is hermetic on developer machines that have a live
	// installation in their real $HOME.
	tmpHome := t.TempDir()
	prevOC := connector.OpenClawHomeOverride
	connector.OpenClawHomeOverride = filepath.Join(tmpHome, ".openclaw")
	if err := os.MkdirAll(connector.OpenClawHomeOverride, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connector.OpenClawHomeOverride = prevOC })

	prevZC := connector.ZeptoClawConfigPathOverride
	connector.ZeptoClawConfigPathOverride = filepath.Join(tmpHome, ".zeptoclaw", "config.json")
	t.Cleanup(func() { connector.ZeptoClawConfigPathOverride = prevZC })

	prevCC := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = filepath.Join(tmpHome, ".claude", "settings.json")
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = prevCC })

	prevCodex := connector.CodexConfigPathOverride
	connector.CodexConfigPathOverride = filepath.Join(tmpHome, ".codex", "config.toml")
	t.Cleanup(func() { connector.CodexConfigPathOverride = prevCodex })

	for _, name := range []string{"openclaw", "claudecode", "codex", "zeptoclaw"} {
		c, ok := reg.Get(name)
		if !ok {
			t.Errorf("connector %q not found", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			err := c.VerifyClean(opts)
			if err != nil {
				t.Errorf("VerifyClean on fresh DataDir should return nil, got: %v", err)
			}
		})
	}
}

func TestConnectorToolInspectionModes(t *testing.T) {
	reg := connector.NewDefaultRegistry()
	validModes := map[connector.ToolInspectionMode]bool{
		connector.ToolModePreExecution: true,
		connector.ToolModeResponseScan: true,
		connector.ToolModeBoth:         true,
	}

	for _, name := range reg.Names() {
		c, _ := reg.Get(name)
		mode := c.ToolInspectionMode()
		if !validModes[mode] {
			t.Errorf("connector %q has invalid ToolInspectionMode %q", name, mode)
		}
	}
}

func TestConnectorSubprocessPolicies(t *testing.T) {
	reg := connector.NewDefaultRegistry()
	validPolicies := map[connector.SubprocessPolicy]bool{
		connector.SubprocessSandbox: true,
		connector.SubprocessShims:   true,
		connector.SubprocessNone:    true,
	}

	for _, name := range reg.Names() {
		c, _ := reg.Get(name)
		policy := c.SubprocessPolicy()
		if !validPolicies[policy] {
			t.Errorf("connector %q has invalid SubprocessPolicy %q", name, policy)
		}
	}
}

func TestConnectorSetCredentials(t *testing.T) {
	reg := connector.NewDefaultRegistry()

	for _, name := range reg.Names() {
		c, _ := reg.Get(name)
		t.Run(name, func(t *testing.T) {
			// Should not panic with empty or non-empty credentials.
			c.SetCredentials("", "")
			c.SetCredentials("test-token", "test-master-key")
		})
	}
}
