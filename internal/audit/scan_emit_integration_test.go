// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestEmitScanResult_RoundTripScanFindings(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	ln := 42
	r := &scanner.ScanResult{
		Scanner: "plugin-scanner", Target: "/p", Timestamp: time.Now().UTC(),
		Findings: []scanner.Finding{{
			ID: "f1", Severity: scanner.SeverityHigh, Title: "T", Description: "d",
			Location: "loc", Remediation: "r", Scanner: "plugin-scanner",
			Category: "cat", RuleID: "plugin.cat.slug", LineNumber: &ln,
		}},
		Duration: 5 * time.Millisecond,
	}
	scanID, err := scanner.EmitScanResult(context.Background(), nil, store, nil, r, scanner.AgentIdentity{AgentID: "a1"})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListScanFindings(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	row := rows[0]
	if !row.RuleID.Valid || row.RuleID.String != "plugin.cat.slug" {
		t.Fatalf("rule_id: %+v", row.RuleID)
	}
	if !row.LineNumber.Valid || row.LineNumber.Int64 != 42 {
		t.Fatalf("line: %+v", row.LineNumber)
	}
}
