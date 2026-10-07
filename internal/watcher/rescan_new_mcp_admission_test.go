// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
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
	w.runRescanCycle(context.Background())
	if len(admitted) != 1 || admitted[0].Event.Name != "added" || admitted[0].Verdict != VerdictAllowed {
		t.Fatalf("second cycle admitted %#v, want added allowed", admitted)
	}
	if scans.calls != before {
		t.Fatalf("scan_on_install false still scanned the new server (%d scans)", scans.calls-before)
	}
}
