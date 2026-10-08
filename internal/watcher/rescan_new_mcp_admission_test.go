// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-0132: on a managed gateway (an MCP server source is bound), a server
// that appears after the first rescan gets install admission, so
// admission.mcp.scan_on_install: false admits it without a scan, as `mcp
// set` does per user. Servers present at start only get baselines.
func TestRescanAdmitsMCPServerAddedLaterWithoutScan(t *testing.T) {
	t.Setenv("PATH", "")
	cfg, store, logger, _ := setupTestEnv(t)
	off := false
	cfg.Admission.MCP.ScanOnInstall = &off
	cfg.Watch.RescanContentGated = true // the unchanged server is not rescanned
	servers := []config.MCPServerEntry{{Name: "present", URL: "https://present.example.test/mcp", Connector: "codex"}}
	var admitted []AdmissionResult
	w := New(cfg, nil, nil, store, logger, nil, func(r AdmissionResult) { admitted = append(admitted, r) })
	scans := &countingScanner{name: "mcp-scanner"}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return scans }
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return servers, nil })

	w.runRescanCycle(context.Background())
	if len(admitted) != 0 {
		t.Fatalf("first cycle admitted %#v, want baselines only", admitted)
	}
	servers = append(servers, config.MCPServerEntry{Name: "added", URL: "https://added.example.test/mcp", Connector: "codex"})
	before := scans.calls
	// GAP-0254: the enrolled-MCP poll admits it at once, not after the cycle.
	w.AdmitAddedMCPServers([]string{"added"})
	w.admitAddedMCPServers(context.Background())
	if len(admitted) != 1 || admitted[0].Event.Name != "added" || admitted[0].Verdict != VerdictAllowed {
		t.Fatalf("poll admitted %#v, want added allowed", admitted)
	}
	if scans.calls != before {
		t.Fatalf("scan_on_install false still scanned the new server (%d scans)", scans.calls-before)
	}
	w.runRescanCycle(context.Background())
	if len(admitted) != 1 {
		t.Fatalf("the next cycle admitted the server again: %#v", admitted)
	}
}

// GAP-0405: servers added with 'claude mcp add' (local scope) or a project's
// .mcp.json were never scanned: the gateway read only the user scope and the
// rescan admitted nothing new. ReadWatchedMCPServers lists every project's
// servers and the discovery poll admits one within its interval.
func TestProjectMCPServerIsAdmittedOnDiscovery(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	state := `{"projects":{"` + filepath.ToSlash(project) + `":{"mcpServers":{"deepwiki":{"type":"http","url":"https://mcp.example.test/mcp"}}}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".mcp.json"), []byte(`{"mcpServers":{"team-sync":{"command":"python3","args":["sync.py"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Watch.RescanEnabled = true
	var admitted []AdmissionResult
	w := New(cfg, nil, nil, store, logger, nil, func(r AdmissionResult) { admitted = append(admitted, r) })
	scans := &countingScanner{name: "mcp-scanner"}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return scans }
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) {
		return cfg.ReadWatchedMCPServers([]string{"claudecode"})
	})
	w.SetMCPDiscoveryPoll(true)
	w.firstCycleDone.Store(true)

	w.discoverAddedMCPServers()
	w.admitAddedMCPServers(context.Background())
	names := map[string]bool{}
	for _, r := range admitted {
		names[r.Event.Name] = true
	}
	if !names["deepwiki"] || !names["team-sync"] || scans.calls != 2 {
		t.Fatalf("admitted %v with %d scans, want deepwiki and team-sync scanned", names, scans.calls)
	}
}
