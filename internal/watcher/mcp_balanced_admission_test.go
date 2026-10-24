// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestBalancedMCPHighAdmissionWarnsAndAudits(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	server := enrolledMCPServer(t.TempDir(), "1001", "@upstash/context7-mcp")
	server.Name = "context7"
	rows := auditRows(t, logger)
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &countingScanner{name: "mcp-scanner", findings: []scanner.Finding{{
			ID: "mcp-YARA-0", RuleID: "coercive_injection", Severity: scanner.SeverityHigh,
			Title: "ordinary tool ordering", Location: "tool:resolve-library-id",
		}}}
	}
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{server}, nil })
	evt := InstallEvent{Type: InstallMCP, Name: server.Name, Path: MCPEventPath(server), Connector: server.Connector}
	res := w.runAdmission(context.Background(), evt)
	if res.Verdict != VerdictWarning || res.MaxSeverity != "HIGH" {
		t.Fatalf("balanced admission %+v, want HIGH warning", res)
	}
	if entry, err := store.GetActionForConnector("mcp", MCPJournalName(server), "claudecode"); err != nil || (entry != nil && !entry.Actions.IsEmpty()) {
		t.Fatalf("balanced journal %+v (err %v), want server callable", entry, err)
	}
	if got := strings.Join(rows(), "\n"); !strings.Contains(got, "install-warning") || !strings.Contains(got, "severity=HIGH") {
		t.Fatalf("audit rows %s, want HIGH install warning", got)
	}

	cfg.Admission.MCP.Actions.High = &config.AdmissionAction{Shorthand: config.AdmissionActionQuarantine}
	res = w.runAdmission(context.Background(), evt)
	if res.Verdict != VerdictRejected {
		t.Fatalf("strict admission %+v, want rejection", res)
	}
	if entry, err := store.GetActionForConnector("mcp", MCPJournalName(server), "claudecode"); err != nil || entry == nil || entry.Actions.Runtime != "disable" {
		t.Fatalf("strict journal %+v (err %v), want disabled", entry, err)
	}
}
