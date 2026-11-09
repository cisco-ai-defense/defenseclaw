// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The reader names the project folder of a server a local or .mcp.json scope
// lists, and leaves it empty for the user scope, so a record kept per config
// scope can tell the three apart.
func TestClaudeCodeMCPReaderNamesTheProjectOfALocalOrProjectScope(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	state, err := json.Marshal(map[string]any{
		"mcpServers": map[string]any{"user-srv": map[string]any{"command": "npx"}},
		"projects": map[string]any{project: map[string]any{"mcpServers": map[string]any{
			"local-srv": map[string]any{"command": "x"},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), state, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".mcp.json"), []byte(`{"mcpServers":{"repo-srv":{"command":"y"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"user-srv": "", "local-srv": project, "repo-srv": project} {
		entry, ok := LookupMCPServerUnderHome("claudecode", home, project, name)
		if !ok {
			t.Fatalf("%s was not read", name)
		}
		if entry.Project != want {
			t.Errorf("%s: Project = %q, want %q", name, entry.Project, want)
		}
	}
}
