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

package inventory

import (
	"path/filepath"
	"sort"
	"testing"
)

// TestDetectMCPPaths_EmitsOneSignalPerServer pins the item-level grain
// switch for `mcp_server`: a two-server mcp.json produces two signals
// with distinct signal_ids and item_name / item_kind / agent_kind
// stamped from the parent signature.
func TestDetectMCPPaths_EmitsOneSignalPerServer(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	mcpPath := filepath.Join(home, ".cursor", "mcp.json")
	mustWrite(t, mcpPath, `{
  "mcpServers": {
    "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "transport": "stdio"},
    "playwright": {"url": "https://mcp.example.com/pw", "transport": "sse"}
  }
}`)

	sig := AISignature{
		ID:                 "cursor",
		Name:               "Cursor",
		Vendor:             "Anysphere",
		Category:           SignalSupportedConnector,
		SupportedConnector: "cursor",
		Confidence:         0.95,
		MCPPaths:           []string{"~/.cursor/mcp.json"},
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true,
		HomeDir: home,
		DataDir: filepath.Join(tmp, "data"),
	}, []AISignature{sig}, nil, nil)

	got := svc.detectMCPPaths()
	if len(got) != 2 {
		t.Fatalf("detectMCPPaths returned %d signals, want 2: %+v", len(got), got)
	}

	names := []string{got[0].ItemName, got[1].ItemName}
	sort.Strings(names)
	if names[0] != "github" || names[1] != "playwright" {
		t.Fatalf("item names = %v, want [github playwright]", names)
	}

	for _, s := range got {
		if s.ItemKind != "mcp_server" {
			t.Fatalf("item_kind = %q, want mcp_server", s.ItemKind)
		}
		if s.AgentKind != "cursor" {
			t.Fatalf("agent_kind = %q, want cursor", s.AgentKind)
		}
		if s.Category != SignalMCPServer {
			t.Fatalf("category = %q, want %q", s.Category, SignalMCPServer)
		}
	}

	if got[0].Fingerprint == got[1].Fingerprint {
		t.Fatalf("fingerprints collide across servers: %q", got[0].Fingerprint)
	}
}

// TestDetectMCPPaths_FallsBackToFileSignalOnParseError ensures a
// malformed mcp.json degrades gracefully into a single file-level
// signal instead of vanishing.
func TestDetectMCPPaths_FallsBackToFileSignalOnParseError(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	mustWrite(t, filepath.Join(home, ".cursor", "mcp.json"), `not a json`)

	sig := AISignature{
		ID:                 "cursor",
		Name:               "Cursor",
		Vendor:             "Anysphere",
		Category:           SignalSupportedConnector,
		SupportedConnector: "cursor",
		Confidence:         0.95,
		MCPPaths:           []string{"~/.cursor/mcp.json"},
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true,
		HomeDir: home,
		DataDir: filepath.Join(tmp, "data"),
	}, []AISignature{sig}, nil, nil)

	got := svc.detectMCPPaths()
	if len(got) != 1 {
		t.Fatalf("expected fallback file-level signal, got %d: %+v", len(got), got)
	}
	if got[0].ItemKind != "" || got[0].ItemName != "" {
		t.Fatalf("fallback signal should carry no item metadata, got kind=%q name=%q", got[0].ItemKind, got[0].ItemName)
	}
	if got[0].AgentKind != "cursor" {
		t.Fatalf("fallback signal agent_kind = %q, want cursor", got[0].AgentKind)
	}
}

// TestDetectSkills_EmitsOneSignalPerChild pins the item-level grain
// for plugin/rule/skill detectors: one signal per non-hidden child in
// the directory, hidden entries (dotfiles) skipped.
func TestDetectSkills_EmitsOneSignalPerChild(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	skillsDir := filepath.Join(home, ".claude", "skills")
	mustWrite(t, filepath.Join(skillsDir, "run-tests.md"), "# skill body")
	mustWrite(t, filepath.Join(skillsDir, "review-diff.md"), "# skill body")
	mustWrite(t, filepath.Join(skillsDir, ".DS_Store"), "junk")

	sig := AISignature{
		ID:                 "claudecode",
		Name:               "Claude Code",
		Vendor:             "Anthropic",
		Category:           SignalSupportedConnector,
		SupportedConnector: "claudecode",
		Confidence:         0.98,
		SkillPaths:         []string{"~/.claude/skills"},
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true,
		HomeDir: home,
		DataDir: filepath.Join(tmp, "data"),
	}, []AISignature{sig}, nil, nil)

	got := svc.detectSkills()
	if len(got) != 2 {
		t.Fatalf("detectSkills returned %d signals, want 2: %+v", len(got), got)
	}
	names := []string{got[0].ItemName, got[1].ItemName}
	sort.Strings(names)
	if names[0] != "review-diff.md" || names[1] != "run-tests.md" {
		t.Fatalf("skill item names = %v, want [review-diff.md run-tests.md]", names)
	}
	for _, s := range got {
		if s.ItemKind != "skill" {
			t.Fatalf("item_kind = %q, want skill", s.ItemKind)
		}
		if s.AgentKind != "claudecode" {
			t.Fatalf("agent_kind = %q, want claudecode", s.AgentKind)
		}
		if s.Category != SignalSkill {
			t.Fatalf("category = %q, want %q", s.Category, SignalSkill)
		}
	}
}

// TestAgentKindForSignature_PromotesDiscoveryOnlyAgents pins the
// promotion table: aider / continue / cline / claude-desktop get an
// agent_kind even though their catalog `supported_connector` is empty,
// and a signature already carrying supported_connector wins.
func TestAgentKindForSignature_PromotesDiscoveryOnlyAgents(t *testing.T) {
	cases := []struct {
		sig  AISignature
		want string
	}{
		{AISignature{ID: "aider"}, "aider"},
		{AISignature{ID: "continue"}, "continue"},
		{AISignature{ID: "cline"}, "cline"},
		{AISignature{ID: "claude-desktop"}, "claudedesktop"},
		{AISignature{ID: "cursor", SupportedConnector: "cursor"}, "cursor"},
		// Explicit override wins over the promotion table entry.
		{AISignature{ID: "aider", SupportedConnector: "openclaw"}, "openclaw"},
		// Unknown signatures return the empty string.
		{AISignature{ID: "unknown-sig"}, ""},
	}
	for _, tc := range cases {
		if got := AgentKindForSignature(tc.sig); got != tc.want {
			t.Errorf("AgentKindForSignature(%+v) = %q, want %q", tc.sig, got, tc.want)
		}
	}
}

// TestBuildAIDiscoveryPayload_CarriesItemFields ensures the wire
// payload preserves the item-level metadata AISignal carries, both in
// redacted and disable-redaction modes.
func TestBuildAIDiscoveryPayload_CarriesItemFields(t *testing.T) {
	sig := AISignal{
		SignalID:  "sig-1",
		Category:  SignalMCPServer,
		Vendor:    "Cursor",
		Product:   "Cursor",
		State:     AIStateNew,
		AgentKind: "cursor",
		ItemKind:  "mcp_server",
		ItemName:  "github",
		ItemAttributes: map[string]string{
			"transport":        "stdio",
			"command_basename": "npx",
		},
	}
	for _, disable := range []bool{false, true} {
		out := BuildAIDiscoveryPayload(sig, "scan-1", PayloadOpts{DisableRedaction: disable})
		if out.AgentKind != "cursor" {
			t.Fatalf("disable=%v: AgentKind=%q want cursor", disable, out.AgentKind)
		}
		if out.ItemKind != "mcp_server" || out.ItemName != "github" {
			t.Fatalf("disable=%v: item metadata missing: kind=%q name=%q", disable, out.ItemKind, out.ItemName)
		}
		if out.ItemAttributes["transport"] != "stdio" {
			t.Fatalf("disable=%v: transport attr = %q, want stdio", disable, out.ItemAttributes["transport"])
		}
	}
}
