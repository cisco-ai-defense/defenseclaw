// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// GAP-0643: a clean registry server (npx -y @modelcontextprotocol/server-filesystem
// <the project folder>) added by an argv-form "mcp add" (the Codex shell tool)
// or by a Write of an MCP config the connector does not load, through the
// files a real actor's kit sends, into the shipped gateway scanner. With the
// kit's folder facts it is scanned and allowed in the default and strict rule
// packs, as rel allowed it; a folder that resolves the fetcher locally
// (.npmrc, node_modules/.bin, a package.json bin) leaves it unscanned, so the
// fail mode decides (GAP-0573 unchanged).
func TestGAP0643ShippedGatewayArgvMCPAddAndUnloadedWriteWithKitFacts(t *testing.T) {
	const srv = "@modelcontextprotocol/server-filesystem"
	shapes := []struct {
		name, connector, tool string
		input                 func(repo string) map[string]any
	}{
		{"codex shell bash -lc codex mcp add", "codex", "shell", func(repo string) map[string]any {
			return map[string]any{"command": []any{"bash", "-lc", "codex mcp add fs -- npx -y " + srv + " " + repo}}
		}},
		{"codex shell argv codex mcp add", "codex", "shell", func(repo string) map[string]any {
			return map[string]any{"command": []any{"codex", "mcp", "add", "fs", "--", "npx", "-y", srv, repo}}
		}},
		{"claude code argv claude mcp add", "claudecode", "Bash", func(repo string) map[string]any {
			return map[string]any{"command": []any{"claude", "mcp", "add", "fs", "--", "npx", "-y", srv, repo}}
		}},
		{"Write of an unloaded sub/.mcp.json", "claudecode", "Write", func(repo string) map[string]any {
			doc, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{
				"fs": map[string]any{"command": "npx", "args": []string{"-y", srv, repo}}}})
			return map[string]any{"file_path": filepath.Join(repo, "sub", ".mcp.json"), "content": string(doc)}
		}},
	}
	bin := filepath.Join(t.TempDir(), "skill-scanner")
	scanner := func(pack string) gateway.AttestMCPScanner {
		c := config.DefaultConfig()
		c.Scanners.SkillScanner.Binary = bin
		if pack != "" {
			c.Guardrail.RulePack = pack
		}
		return gateway.AttestMCPScanner{RT: newRuntimeSkillScanner(c).rt}
	}
	// run sets up a fresh project folder (local adds files a fetcher would
	// resolve there), collects the kit's facts for the call and returns the
	// shipped gateway's decision for the server fs.
	run := func(t *testing.T, connector, tool string, input func(string) map[string]any, local map[string]string, pack string, noFacts bool) gateway.SubstrateMCPDecision {
		t.Helper()
		home := t.TempDir()
		t.Setenv("HOME", home) // the kit reads user-scope MCP configs and stops its walk at HOME
		t.Setenv("CLAUDE_CONFIG_DIR", "")
		t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
		repo := filepath.Join(home, "work")
		if err := os.MkdirAll(filepath.Join(repo, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		for rel, body := range local {
			p := filepath.Join(repo, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input(repo), "cwd": repo})
		var files []gateway.SubstrateAttachedFile
		checked := false
		if kf := kit.CollectFacts(connector, "PreToolUse", payload, kit.MaxAttachBytes); kf != nil && !noFacts {
			for _, f := range kf.Files {
				files = append(files, gateway.SubstrateAttachedFile{Role: f.Role, Path: f.Path, Content: f.Content, Truncated: f.Truncated})
				checked = checked || f.Role == "mcp_fetch_checked"
			}
		}
		if !noFacts && !checked {
			t.Fatalf("the kit sent no folder record: %+v", files)
		}
		ds, err := scanner(pack).ScanMCP(context.Background(), payload, files)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range ds {
			if d.Server == "fs" {
				return d
			}
		}
		t.Fatalf("no decision for the server: %+v", ds)
		return gateway.SubstrateMCPDecision{}
	}
	locals := map[string]map[string]string{
		".npmrc":            {".npmrc": "node-options=--require ./x.js\n"},
		"node_modules/.bin": {"node_modules/.bin/mcp-server-filesystem": "#!/bin/sh\n"},
		"package.json bin":  {"package.json": `{"name":"p","bin":{"mcp-server-filesystem":"x.js"}}`},
	}
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			for _, pack := range []string{"", "strict"} {
				// Read and decided by the config rules (allowed, at most a
				// warning such as an unpinned package), not unscanned.
				if d := run(t, s.connector, s.tool, s.input, nil, pack, false); d.Block || d.Unreadable {
					t.Errorf("pack %q: the clean fetched server with the kit's folder facts: %+v, want scanned and allowed", pack, d)
				}
				// Without the folder facts: not known, the fail mode decides.
				if d := run(t, s.connector, s.tool, s.input, nil, pack, true); !d.Unreadable || d.Block {
					t.Errorf("pack %q: without folder facts: %+v, want unreadable", pack, d)
				}
			}
			for name, files := range locals {
				if d := run(t, s.connector, s.tool, s.input, files, "", false); !d.Unreadable {
					t.Errorf("a folder with %s: %+v, want unreadable", name, d)
				}
			}
		})
	}
}
