// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"fmt"
	"strings"
	"testing"
)

// GAP-0686: a claim about a source the enumerator does not publish keeps its
// name, source marks and digest when the definition does not fit the bounds,
// so the gateway never falls back to the files it reads; a claim without such
// a mark is dropped as before, and a digest that is not a SHA-256 is dropped.
func TestMCPClaimOfAnUnpublishedSourceSurvivesTheBounds(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	long := "https://example.invalid/mcp?value=" + strings.Repeat("a", 1100)
	args := make([]string, 33)
	for i := range args {
		args[i] = fmt.Sprintf("arg%d", i)
	}
	for _, tc := range []struct {
		name   string
		server MCPServer
		keep   bool
		bare   bool
	}{
		{"long URL, session-only CODEX_HOME", MCPServer{Name: "notes", URL: long, Relocated: true, Digest: digest}, true, true},
		{"33 arguments, session-only CODEX_HOME", MCPServer{Name: "notes", Command: "node", Args: args, Relocated: true, Digest: digest}, true, true},
		{"long URL, project config", MCPServer{Name: "notes", URL: long, ProjectScope: true, Digest: digest}, true, true},
		{"fits, session-only CODEX_HOME", MCPServer{Name: "notes", URL: "http://127.0.0.1:1/mcp", Relocated: true, Digest: digest}, true, false},
		{"long URL, ordinary source", MCPServer{Name: "notes", URL: long}, false, false},
	} {
		got, ok := Decode(Encode(Facts{MCP: &tc.server}))
		if tc.keep != (ok && got.MCP != nil) {
			t.Errorf("%s: claim kept = %v, want %v", tc.name, ok && got.MCP != nil, tc.keep)
			continue
		}
		if !tc.keep {
			continue
		}
		m := got.MCP
		if m.Name != "notes" || m.Relocated != tc.server.Relocated || m.ProjectScope != tc.server.ProjectScope || m.Digest != digest {
			t.Errorf("%s: claim = %+v, want the name, source mark and digest kept", tc.name, m)
		}
		if tc.bare && (m.URL != "" || m.Command != "" || len(m.Args) != 0) {
			t.Errorf("%s: claim = %+v, want the definition that does not fit dropped, not truncated", tc.name, m)
		}
	}
	got, _ := Decode(Encode(Facts{MCP: &MCPServer{Name: "notes", URL: "http://127.0.0.1:1/mcp", Relocated: true, Digest: "not-a-digest"}}))
	if got.MCP == nil || got.MCP.Digest != "" {
		t.Errorf("a digest that is not a SHA-256 was kept: %+v", got.MCP)
	}
}
