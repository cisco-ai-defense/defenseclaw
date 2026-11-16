// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// An unfinished scan is an admission outcome for the current definition,
// including a changed one. Its baseline must also make the next rescan use
// admission, so the first completed verdict is enforced rather than merely
// recorded as drift.
func TestUnverifiedMCPDefinitionRetriesAdmissionAndEnforcesFirstVerdict(t *testing.T) {
	for _, tc := range []struct {
		name, first, final string
	}{
		{"changed then high", "changed", "high"},
		{"changed then clean", "changed", "clean"},
		{"new then high", "new", "high"},
		{"new then clean", "new", "clean"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := enrolledMCPServer(t.TempDir(), "1001", ".")
			h := newDefinitionChangeHarness(t, server)
			mode := "clean"
			h.w.scannerFactory = func(InstallEvent) scanner.Scanner {
				switch mode {
				case "timeout":
					return &erringScanner{countingScanner: countingScanner{name: "mcp-scanner"}, err: context.DeadlineExceeded}
				case "high":
					return &countingScanner{name: "mcp-scanner", findings: []scanner.Finding{{
						ID: "f1", RuleID: "MCP-001", Severity: scanner.SeverityHigh, Title: "unsafe tool",
					}}}
				default:
					return &countingScanner{name: "mcp-scanner"}
				}
			}
			if tc.first == "changed" {
				if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
					t.Fatalf("initial admission: %+v", got)
				}
				h.servers[0].Args = []string{"-y", ".", "--quiet"}
				if !h.pending(h.servers[0]) {
					t.Fatal("changed definition was not pending before admission")
				}
			}
			mode = "timeout"
			if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictScanError || !strings.HasPrefix(got[0].Reason, unverifiedMCPReason) {
				t.Fatalf("unfinished admission: %+v, want kept unverified", got)
			}
			if h.pending(h.servers[0]) {
				t.Fatal("kept unverified definition is still pending and its tools are blocked")
			}
			checkBaseline := func() {
				t.Helper()
				row, err := h.store.GetTargetSnapshot(string(InstallMCP), MCPEventPath(h.servers[0]))
				if err != nil {
					t.Fatal(err)
				}
				if row.ScanID != "" || !strings.HasSuffix(row.ScannerFingerprint, "|mcp-unverified") || !mcpBaselineMatches(row, h.servers[0]) {
					t.Fatalf("baseline %+v, want current definition marked unverified for retry", row)
				}
			}
			// Clean cases inspect the marker; HIGH cases prove that it drives
			// the later scan through admission and disables the server.
			if tc.final == "clean" {
				checkBaseline()
			}

			evt := InstallEvent{Type: InstallMCP, Name: h.servers[0].Name, Path: MCPEventPath(h.servers[0]), Connector: h.servers[0].Connector}
			if got := h.w.rescanTarget(context.Background(), evt, nil); got != rescanScanned {
				t.Fatalf("unfinished retry outcome %v, want scanned", got)
			}
			if tc.final == "clean" {
				checkBaseline()
			}
			if h.pending(h.servers[0]) {
				t.Fatal("an unfinished retry put the server back behind the pending gate")
			}

			mode = tc.final
			before := len(h.admitted)
			if got := h.w.rescanTarget(context.Background(), evt, nil); got != rescanScanned {
				t.Fatalf("completed retry outcome %v, want scanned", got)
			}
			if len(h.admitted) != before+1 {
				t.Fatalf("completed scan had no admission verdict: %+v", h.admitted[before:])
			}
			row, err := h.store.GetTargetSnapshot(string(InstallMCP), evt.Path)
			if err != nil {
				t.Fatal(err)
			}
			if row.ScanID == "" || strings.HasSuffix(row.ScannerFingerprint, "|mcp-unverified") {
				t.Fatalf("completed admission kept an unverified baseline: %+v", row)
			}
			if h.pending(h.servers[0]) {
				t.Fatal("server remained pending after completed admission")
			}
			state := h.journal(h.servers[0])
			if tc.final == "high" {
				if h.admitted[before].Verdict != VerdictRejected || state.Runtime != "disable" || state.Install != "block" {
					t.Fatalf("HIGH verdict %+v, journal %+v; want rejected and disabled", h.admitted[before], state)
				}
			} else if h.admitted[before].Verdict != VerdictClean || !state.IsEmpty() {
				t.Fatalf("clean verdict %+v, journal %+v; want callable", h.admitted[before], state)
			}
		})
	}
}
