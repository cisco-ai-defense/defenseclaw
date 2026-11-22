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

package workspace

import (
	"strings"
	"testing"
)

// GAP-0473: files an agent or a shell runs from the folder are flagged as
// able to run code, each with its own reason, on the one list that Substrate
// pull and OpenShell copy mode share: agent settings (hook registration),
// MCP server config and shell startup files.
func TestGAP0473AgentSettingsMCPAndShellRCAreFlagged(t *testing.T) {
	noContent := func(TreeChange, bool) ([]byte, bool) { return nil, false }
	want := map[string]string{
		".claude/settings.json":       "hooks",
		".claude/settings.local.json": "hooks",
		".claude/hooks/start.sh":      "hooks",
		".codex/config.toml":          "hooks",
		".cursor/hooks.json":          "hooks",
		".gemini/settings.json":       "hooks",
		".mcp.json":                   "MCP servers",
		".cursor/mcp.json":            "MCP servers",
		".vscode/mcp.json":            "MCP servers",
		".bashrc":                     "shell",
		".zshrc":                      "shell",
		".profile":                    "shell",
	}
	var changes []TreeChange
	for p := range want {
		changes = append(changes, TreeChange{Path: p, Status: "A", NewMode: "100644"})
	}
	changes = append(changes, TreeChange{Path: "README.md", Status: "A", NewMode: "100644"},
		TreeChange{Path: ".claude/agents/reviewer.md", Status: "A", NewMode: "100644"})
	got := map[string]Flag{}
	for _, f := range classifyChanges(changes, noContent, nil) {
		got[f.Path] = f
	}
	for p, word := range want {
		f, ok := got[p]
		if !ok || f.Severity != SeverityHigh || !strings.Contains(f.Detail, word) {
			t.Errorf("%s: flag %+v, want severity high and a reason naming %q", p, f, word)
		}
	}
	for _, p := range []string{"README.md", ".claude/agents/reviewer.md"} {
		if f, ok := got[p]; ok {
			t.Errorf("%s flagged: %+v", p, f)
		}
	}
	rep := &ReviewReport{Flags: classifyChanges([]TreeChange{{Path: ".mcp.json", Status: "A", NewMode: "100644"}}, noContent, nil)}
	if !rep.Sensitive() {
		t.Error("a pull that adds only .mcp.json is not sensitive")
	}
}
