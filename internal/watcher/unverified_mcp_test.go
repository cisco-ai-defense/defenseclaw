// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// erringScanner fails every scan with err, after reporting findings (a
// scanner that exited non-zero with partial output) and running during (a
// policy change while the scan runs).
type erringScanner struct {
	countingScanner
	err    error
	during func()
}

func (s *erringScanner) Scan(context.Context, string) (*scanner.ScanResult, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	if s.during != nil {
		s.during()
	}
	var result *scanner.ScanResult
	if len(s.findings) > 0 {
		result = &scanner.ScanResult{Scanner: s.name, Findings: s.findings}
	}
	return result, s.err
}

// GAP-1195 (review loop 2): mcp set adds a server whose pre-add scan did not
// finish, with a warning, in the default tier; the gateway watcher then
// blocked and disabled it when its own scan failed the same way, because it
// never read scanners.mcp_scanner.unverified_server. The watcher keeps such a
// server under warn (audited, scanned again later) and blocks it under block,
// a scanner refusal of the server's
// definition, a partial scan with findings, and a block the policy adds while
// the scan runs. A skill whose scan fails is still blocked in every tier.
func TestUnverifiedMCPServerFollowsTheUnverifiedServerSetting(t *testing.T) {
	timeout := fmt.Errorf("scanner: mcp-scanner could not complete: %w", context.DeadlineExceeded)
	refusal := fmt.Errorf("scanner: mcp-scanner exited 1: %w", scanner.ErrMCPScanRefused)
	for _, tc := range []struct {
		name      string
		setting   string
		managed   bool
		err       error
		findings  []scanner.Finding
		blockMid  bool
		wantKept  bool
		typeSkill bool
	}{
		{name: "default timeout is kept", err: timeout, wantKept: true},
		{name: "default exit is kept", err: fmt.Errorf("mcp-scanner exited 1"), wantKept: true},
		{name: "warn on managed standalone is kept", setting: "warn", managed: true, err: timeout, wantKept: true},
		{name: "block is blocked", setting: "block", err: timeout},
		{name: "unset on managed standalone is kept", managed: true, err: timeout, wantKept: true},
		{name: "scanner refusal is blocked", err: refusal},
		{name: "child refusal text is blocked", err: fmt.Errorf("scanner: mcp-scanner exited 1: ValueError: refusing to scan local MCP server %q: node is not npx or uvx", "context7")},
		{name: "partial scan with findings is blocked", err: fmt.Errorf("mcp-scanner exited 3"),
			findings: []scanner.Finding{{ID: "f1", RuleID: "MCP-001", Severity: scanner.SeverityHigh, Title: "coercive"}}},
		{name: "block added during the scan is blocked", err: timeout, blockMid: true},
		{name: "skill scan failure is blocked", err: timeout, typeSkill: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, logger, skillDir := setupTestEnv(t)
			rows := auditRows(t, logger)
			cfg.Scanners.MCPScanner.UnverifiedServer = tc.setting
			if tc.managed {
				cfg.DeploymentMode = "managed_enterprise"
				cfg.Enterprise.Profile = "standalone"
			}
			w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
			failing := &erringScanner{countingScanner: countingScanner{name: "mcp-scanner", findings: tc.findings}, err: tc.err}
			evt := InstallEvent{Type: InstallMCP, Name: "context7", Path: "mcp:codex:context7", Connector: "codex", Timestamp: time.Now()}
			journalType, journalName := "mcp", "context7"
			if tc.typeSkill {
				failing.name = "skill-scanner"
				path := filepath.Join(skillDir, "notes")
				if err := os.MkdirAll(path, 0o700); err != nil {
					t.Fatal(err)
				}
				evt = InstallEvent{Type: InstallSkill, Name: "notes", Path: path, Timestamp: time.Now()}
				journalType, journalName = "skill", "notes"
			}
			if tc.blockMid {
				failing.during = func() {
					cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: "context7", Reason: "reviewed"}}
				}
			}
			w.scannerFactory = func(InstallEvent) scanner.Scanner { return failing }
			res := w.runAdmission(context.Background(), evt)
			scope := w.journalScope(w.eventConnector(evt))
			entry, err := store.GetActionForConnector(journalType, journalName, scope)
			if err != nil {
				t.Fatal(err)
			}
			blocked := entry != nil && entry.Actions.Install == "block"
			if tc.wantKept {
				if res.Verdict != VerdictScanError || res.RuntimeAction != "" || blocked ||
					!strings.HasPrefix(res.Reason, unverifiedMCPReason) {
					t.Fatalf("result %+v journal %+v, want the server kept unverified", res, entry)
				}
				got := strings.Join(rows(), "\n")
				if !strings.Contains(got, "install-scan-error") || !strings.Contains(got, "reason=unverified") {
					t.Fatalf("audit rows:\n%s\nwant install-scan-error and an install-allowed reason=unverified row", got)
				}
				return
			}
			if tc.blockMid {
				if res.Verdict != VerdictBlocked {
					t.Fatalf("result %+v, want blocked", res)
				}
				return
			}
			if res.Verdict != VerdictBlocked || res.RuntimeAction != "block" || !blocked || entry.Actions.Runtime != "disable" {
				t.Fatalf("result %+v journal %+v, want blocked and disabled", res, entry)
			}
		})
	}
}

// Under warn, a block an earlier failed scan left (unverified_server was
// block then) is released when the next scan again does not finish: the
// setting now keeps such a server. A block for findings stays.
func TestUnverifiedMCPServerReleasesAnEarlierScanFailureBlockOnly(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Scanners.MCPScanner.UnverifiedServer = "block"
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &erringScanner{countingScanner: countingScanner{name: "mcp-scanner"}, err: context.DeadlineExceeded}
	}
	evt := InstallEvent{Type: InstallMCP, Name: "notes", Path: "mcp:codex:notes", Connector: "codex", Timestamp: time.Now()}
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("block: result %+v, want blocked", res)
	}
	cfg.Scanners.MCPScanner.UnverifiedServer = "warn"
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictScanError {
		t.Fatalf("warn: result %+v, want kept unverified", res)
	}
	if entry, err := store.GetActionForConnector("mcp", "notes", "codex"); err != nil || (entry != nil && !entry.Actions.IsEmpty()) {
		t.Fatalf("journal %+v (err %v), want the scan failure block released", entry, err)
	}

	const findingsBlock = "admin block"
	if err := store.SetActionFieldForConnector("mcp", "notes", "codex", "install", "block", findingsBlock); err != nil {
		t.Fatal(err)
	}
	w.runAdmission(context.Background(), evt)
	if entry, err := store.GetActionForConnector("mcp", "notes", "codex"); err != nil || entry == nil || entry.Actions.Install != "block" {
		t.Fatalf("journal %+v (err %v), want the other block kept", entry, err)
	}
}
