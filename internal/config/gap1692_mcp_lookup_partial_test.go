// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const gap1692URL = "http://127.0.0.1:28593/mcp"

func gap1692Write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// GAP1692Sources sets up, for one connector, a good source the user owns
// that configures "notes" (and, for Codex, two names that share a tool
// segment) next to a bad source a repository can plant in the workspace.
func gap1692Sources(t *testing.T, connector, home, workspace, bad string) {
	t.Helper()
	switch connector {
	case "codex":
		t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
		gap1692Write(t, filepath.Join(home, ".codex", "config.toml"),
			"[mcp_servers.notes]\nurl = \""+gap1692URL+"\"\n"+
				"[mcp_servers.acme-notes]\ncommand = \"node\"\n"+
				"[mcp_servers.acme_notes]\ncommand = \"uvx\"\n")
		gap1692Write(t, filepath.Join(workspace, ".codex", "config.toml"), bad)
	case "antigravity":
		gap1692Write(t, filepath.Join(home, ".gemini", "config", "mcp_config.json"),
			`{"mcpServers":{"notes":{"serverUrl":"`+gap1692URL+`"}}}`)
		gap1692Write(t, filepath.Join(workspace, ".agents", "mcp_config.json"), bad)
	case "amp":
		gap1692Write(t, filepath.Join(home, ".config", "amp", "settings.json"),
			`{"amp.mcpServers":{"notes":{"url":"`+gap1692URL+`"}}}`)
		gap1692Write(t, filepath.Join(workspace, ".amp", "settings.json"), bad)
	case "copilot":
		gap1692Write(t, filepath.Join(home, ".copilot", "mcp-config.json"),
			`{"mcpServers":{"notes":{"type":"http","url":"`+gap1692URL+`"}}}`)
		gap1692Write(t, filepath.Join(workspace, ".mcp.json"), bad)
	case "hermes":
		// One user file: a valid mcp_servers table next to a legacy key
		// that does not hold a server collection.
		t.Setenv("HERMES_HOME", filepath.Join(home, ".hermes"))
		gap1692Write(t, filepath.Join(home, ".hermes", "config.yaml"),
			"mcp_servers:\n  notes:\n    url: "+gap1692URL+"\nmcpServers: "+bad+"\n")
	default:
		t.Fatalf("no sources for %s", connector)
	}
}

// GAP-1692: since #1406 the native MCP readers return the servers of every
// source that read plus the first read error, so an inventory pass knows it
// is incomplete. The per-call lookups returned not-found on that error, so a
// repository that planted a malformed or oversized config next to the
// user's own made the user's servers unresolved at the hook: a denied URL
// rule on one of them stopped matching. The lookups use every entry that
// read, as rel did; the inventory read still reports the error.
func TestGAP1692MCPLookupsKeepReadableSourcesWhenOneFails(t *testing.T) {
	oversized := "# " + strings.Repeat("x", maxCodexInventoryConfigBytes) + "\n"
	cases := []struct{ connector, bad string }{
		{"codex", "not = [toml"},
		{"codex", oversized},
		{"antigravity", `{"mcpServers":`},
		{"amp", `{`},
		{"copilot", `{"mcpServers":`},
		{"hermes", `"not a server collection"`},
	}
	for _, tc := range cases {
		name := tc.connector
		if len(tc.bad) > 64 {
			name += "-oversized"
		}
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			testenv.SetHome(t, home)
			workspace := filepath.Join(home, "repo")
			if err := os.MkdirAll(workspace, 0o700); err != nil {
				t.Fatal(err)
			}
			gap1692Sources(t, tc.connector, home, workspace, tc.bad)
			cfg := &Config{}
			check := func(how string, entry MCPServerEntry, ok bool) {
				t.Helper()
				if !ok || entry.Name != "notes" || entry.URL != gap1692URL {
					t.Errorf("%s(%s) next to a bad source: ok=%v entry=%+v, want notes at %s",
						how, tc.connector, ok, entry, gap1692URL)
				}
			}
			entry, ok := cfg.LookupMCPToolServerForConnector(tc.connector, workspace, "notes")
			check("LookupMCPToolServerForConnector", entry, ok)
			// The standalone hook (hook_asset_facts.go) has no config.
			entry, ok = (*Config)(nil).LookupMCPToolServerForConnector(tc.connector, workspace, "notes")
			check("nil LookupMCPToolServerForConnector", entry, ok)
			// The Secure Client path.
			entry, ok = cfg.LookupMCPServerForConnector(tc.connector, workspace, "notes")
			check("LookupMCPServerForConnector", entry, ok)
			if tc.connector == "codex" && !cfg.CodexMCPToolServerAmbiguous(workspace, "acme_notes") {
				t.Error("CodexMCPToolServerAmbiguous next to a bad project config = false, want the colliding user servers ambiguous")
			}

			// Inventory completeness keeps the error (#1406, GAP-1687).
			cfg.Claw.WorkspaceDir = workspace
			entries, err := cfg.ReadMCPServersForConnector(tc.connector)
			if !hasMCPEntry(entries, "notes") {
				t.Errorf("inventory lost the readable server: entries=%+v", entries)
			}
			wantErr := tc.connector != "copilot" // the Copilot reader skips a bad file, as at rel
			if (err != nil) != wantErr {
				t.Errorf("inventory read error = %v, want an error: %v", err, wantErr)
			}
		})
	}
}
