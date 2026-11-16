// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed/mcpasuser"
)

// GAP-0686: every connector the enumerator publishes has its own record
// folder, Codex included, and a connector it does not publish has none. A
// Codex record reads back tagged codex, with its source and its built-in
// marker kept, so the gateway admits the account servers and skips the
// built-in one.
func TestGAP0686EveryPublishedConnectorHasItsOwnSpool(t *testing.T) {
	authorizationDir := t.TempDir()
	seen := map[string]string{}
	codex := false
	for _, published := range mcpasuser.PublishedConnectors() {
		dir := MCPSpoolDir(authorizationDir, published.Connector)
		if dir == "" || filepath.Dir(dir) != authorizationDir || published.Label == "" || published.Unreadable == "" {
			t.Fatalf("%s: spool folder %q, label %q, unreadable code %q", published.Connector, dir, published.Label, published.Unreadable)
		}
		if other, ok := seen[dir]; ok {
			t.Fatalf("%s and %s share the spool folder %s", other, published.Connector, dir)
		}
		seen[dir] = published.Connector
		codex = codex || published.Connector == "codex"
	}
	if !codex {
		t.Fatal("the enumerator does not publish the Codex MCP servers of enrolled accounts")
	}
	if ClaudeMCPSpoolDir(authorizationDir) != filepath.Join(authorizationDir, ClaudeMCPSpoolDirName) ||
		KiroMCPSpoolDir(authorizationDir) != filepath.Join(authorizationDir, KiroMCPSpoolDirName) ||
		MCPSpoolDir(authorizationDir, "codex") != filepath.Join(authorizationDir, CodexMCPSpoolDirName) {
		t.Fatal("a spool folder moved: records an earlier build wrote would no longer be read")
	}
	if dir := MCPSpoolDir(authorizationDir, "opencode"); dir != "" {
		t.Fatalf("an unpublished connector has the spool folder %s", dir)
	}

	const sid = "S-1-5-21-1-1001"
	dir := MCPSpoolDir(authorizationDir, "codex")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "config.toml")
	data, err := MarshalClaudeMCPSpoolRecord(sid, []config.MCPServerEntry{
		{Name: "r109loop", Command: "node", Args: []string{"server.js"}, Source: source, SourceScope: "user"},
		{Name: "openaiDeveloperDocs", URL: "https://developers.openai.com/mcp", Source: source, SourceScope: "user", Bundled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sid+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	servers, unreadable, err := ReadMCPSpool(dir, sid, "codex", nil)
	if err != nil || unreadable != nil || len(servers) != 2 {
		t.Fatalf("read = %+v %v %v", servers, unreadable, err)
	}
	for _, server := range servers {
		if server.Connector != "codex" || server.Source != source || server.Bundled != (server.Name == "openaiDeveloperDocs") {
			t.Fatalf("read back %+v", server)
		}
	}
}
