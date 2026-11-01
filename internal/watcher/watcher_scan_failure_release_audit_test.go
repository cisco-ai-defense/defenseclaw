// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-0289: a scan that later succeeds lifts the install block and runtime
// disable a failed scan of an MCP server left. The release must leave an
// enable audit row naming the cleared block, as the release of a superseded
// rejection does, and a clean scan with no block to lift writes none.
func TestScanFailureBlockReleaseWritesEnableRow(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Scanners.MCPScanner.UnverifiedServer = "block"
	rt := &watcherTestRuntime{}
	logger.SetRuntimeV8Emitter(rt)
	w := New(cfg, nil, nil, store, logger, nil, nil)
	evt := InstallEvent{Type: InstallMCP, Name: "notes", Path: "mcp:codex:notes", Connector: "codex", Timestamp: time.Now()}
	releaseRows := func() []string {
		t.Helper()
		logs, _ := rt.snapshot()
		var rows []string
		for _, record := range logs {
			raw, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if text := string(raw); strings.Contains(text, "cleared the scan-failure block") {
				rows = append(rows, text)
			}
		}
		return rows
	}

	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "mcp-scanner"} }
	w.runAdmission(context.Background(), evt)
	if rows := releaseRows(); len(rows) != 0 {
		t.Fatalf("clean scan with no block: release rows %v, want none", rows)
	}

	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &failingScanner{countingScanner{name: "mcp-scanner"}} }
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("failed scan: result %+v, want blocked", res)
	}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "mcp-scanner"} }
	if res := w.runAdmission(context.Background(), evt); res.Verdict == VerdictBlocked {
		t.Fatalf("clean rescan: result %+v, want the block released", res)
	}
	rows := releaseRows()
	if len(rows) != 1 {
		t.Fatalf("clean rescan after a failed scan: release rows %v, want one enable row", rows)
	}
	for _, want := range []string{`"enable"`, "mcp:codex:notes", "type=mcp released", "install=block", "runtime=disable", "connector=codex"} {
		if !strings.Contains(rows[0], want) {
			t.Fatalf("release row %s, want %q", rows[0], want)
		}
	}

	w.runAdmission(context.Background(), evt)
	if rows := releaseRows(); len(rows) != 1 {
		t.Fatalf("second clean rescan: release rows %v, want still one", rows)
	}
}
