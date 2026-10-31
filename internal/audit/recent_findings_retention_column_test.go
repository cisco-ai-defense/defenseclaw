// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// rel-1-0-6 GAP-0152: the session correlation read asked the schema for the
// retention column on the store's single connection on every hook call. The
// answer is kept once the column exists, and the read orders the same way.
func TestRecentFindingsReadKeepsTheRetentionColumnAnswer(t *testing.T) {
	logger := newTestLogger(t)
	at := time.Date(2026, 10, 31, 3, 0, 0, 0, time.UTC)
	if err := logger.store.InsertScanSummary(scanner.ScanSummaryParams{
		ScanID: "scan-1", Scanner: "hook-rules", Target: "claudecode:PreToolUse",
		Timestamp: at, FindingCount: 1, MaxSeverity: "HIGH", SessionID: "s", AgentInstanceID: "agent",
	}); err != nil {
		t.Fatal(err)
	}
	if err := logger.store.InsertScanFindings("scan-1", "claudecode:PreToolUse", []scanner.Finding{{
		FindingOccurrenceID: "finding-1", Scanner: "hook-rules", RuleID: "R1", Category: "general",
		Severity: scanner.SeverityHigh, Title: "Finding", ContentFingerprint: "fp1",
	}}, scanner.ScanFindingMeta{Timestamp: at, SessionID: "s", AgentInstanceID: "agent"}); err != nil {
		t.Fatal(err)
	}
	if logger.store.findingsRetentionInstant.Load() {
		t.Fatal("retention column answer kept before the first read")
	}
	for i := range 2 {
		rows, err := logger.store.ListRecentFindingsInSession("s", "agent", "", 5)
		if err != nil || len(rows) != 1 || rows[0].ID != "finding-1" {
			t.Fatalf("read %d: rows %#v err %v", i, rows, err)
		}
		if !logger.store.findingsRetentionInstant.Load() {
			t.Fatalf("read %d did not keep the retention column answer", i)
		}
	}
}
