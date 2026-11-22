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

// GAP-0641: the clean registry server of TestGAP0185ShippedGatewayScansRepoMCPServers
// (npx -y @modelcontextprotocol/server-filesystem <the project folder>) through
// the files a real actor's kit sends, into the shipped gateway scanner. The
// kit attaches the repository config and what the folder offers a registry
// fetcher (GAP-0573). In a clean folder the package runs nothing of it, so
// the project folder it is given is data and the config rules decide: the
// server is attached and read, not unscanned, in every rule pack. Without
// the folder facts it is not known and the fail mode decides.
func TestGAP0641ShippedGatewayCleanFetchedServerWithKitFacts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home) // the kit reads user-scope MCP configs and stops its walk at HOME
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	repo := filepath.Join(home, "work")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	doc, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{
		"good": map[string]any{"command": "npx", "args": []string{"-y", "@modelcontextprotocol/server-filesystem", repo}}}})
	if err := os.WriteFile(filepath.Join(repo, ".mcp.json"), doc, 0o644); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "mcp__good__read_file", "tool_input": map[string]any{}, "cwd": repo})
	kf := kit.CollectFacts("claudecode", "PreToolUse", payload, kit.MaxAttachBytes)
	if kf == nil {
		t.Fatal("the kit sent no facts")
	}
	var withFacts, configOnly []gateway.SubstrateAttachedFile
	checked := false
	for _, f := range kf.Files {
		g := gateway.SubstrateAttachedFile{Role: f.Role, Path: f.Path, Content: f.Content, Truncated: f.Truncated}
		withFacts = append(withFacts, g)
		switch f.Role {
		case "mcp_config":
			configOnly = append(configOnly, g)
		case "mcp_fetch_checked":
			checked = true
		}
	}
	if !checked || len(configOnly) != 1 {
		t.Fatalf("kit files: %+v, want the repository config and the folder record", kf.Files)
	}
	good := func(rt gateway.AttestMCPScanner, files []gateway.SubstrateAttachedFile) gateway.SubstrateMCPDecision {
		t.Helper()
		ds, err := rt.ScanMCP(context.Background(), payload, files)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range ds {
			if d.Server == "good" {
				return d
			}
		}
		t.Fatalf("no decision for the server: %+v", ds)
		return gateway.SubstrateMCPDecision{}
	}
	bin := filepath.Join(t.TempDir(), "skill-scanner")
	for _, pack := range []string{"", "strict"} {
		c := config.DefaultConfig()
		c.Scanners.SkillScanner.Binary = bin
		if pack != "" {
			c.Guardrail.RulePack = pack
		}
		rt := gateway.AttestMCPScanner{RT: newRuntimeSkillScanner(c).rt}
		if d := good(rt, withFacts); !d.Attached || d.Block || d.Unreadable {
			t.Errorf("pack %q: the clean fetched server with the kit's folder facts: %+v", pack, d)
		}
		// A kit that did not look at the folder: not known (GAP-0573), so
		// it is unscanned and the fail mode decides, never a silent allow.
		if d := good(rt, configOnly); !d.Unreadable || d.Block {
			t.Errorf("pack %q: the fetched server without folder facts: %+v, want unreadable", pack, d)
		}
	}
	// A folder that redirects the fetcher (.npmrc) is not clean: the fail
	// mode decides again (GAP-0573 stays closed).
	if err := os.WriteFile(filepath.Join(repo, ".npmrc"), []byte("node-options=--require ./x.js\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	kf = kit.CollectFacts("claudecode", "PreToolUse", payload, kit.MaxAttachBytes)
	var redirected []gateway.SubstrateAttachedFile
	for _, f := range kf.Files {
		redirected = append(redirected, gateway.SubstrateAttachedFile{Role: f.Role, Path: f.Path, Content: f.Content, Truncated: f.Truncated})
	}
	c := config.DefaultConfig()
	c.Scanners.SkillScanner.Binary = bin
	if d := good(gateway.AttestMCPScanner{RT: newRuntimeSkillScanner(c).rt}, redirected); !d.Unreadable {
		t.Errorf("a folder with an .npmrc: %+v, want unreadable", d)
	}
}
