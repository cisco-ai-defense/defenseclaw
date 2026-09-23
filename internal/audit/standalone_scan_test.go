// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestPersistStandaloneScanCommitsLifecycleWithoutRuntimeFanout(t *testing.T) {
	if err := NewLogger(nil).PersistStandaloneScan(&scanner.ScanResult{}, nil); err == nil ||
		!strings.Contains(err.Error(), "store is unavailable") {
		t.Fatalf("missing standalone store error = %v", err)
	}
	logger := newTestLogger(t)
	base := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	line := 7
	result := func(at time.Time) *scanner.ScanResult {
		return &scanner.ScanResult{
			Scanner: "codeguard", Target: "/repo", TargetType: "code",
			Timestamp: at, Duration: time.Millisecond,
			Findings: []scanner.Finding{{
				Scanner: "codeguard", RuleID: "CG-EXEC-001",
				Severity: scanner.SeverityHigh, Title: "Unsafe shell execution",
				Description: "os.system(cmd)", Location: "/repo/main.py:7",
				LineNumber: &line,
			}},
		}
	}

	first := result(base)
	if err := logger.PersistStandaloneScan(first, nil); err != nil {
		t.Fatalf("first standalone persistence: %v", err)
	}
	second := result(base.Add(time.Minute))
	if err := logger.PersistStandaloneScan(second, nil); err != nil {
		t.Fatalf("repeated standalone persistence: %v", err)
	}

	counts, err := logger.store.GetCounts()
	if err != nil {
		t.Fatal(err)
	}
	if counts.TotalScans != 2 {
		t.Fatalf("scan_results count = %d, want 2", counts.TotalScans)
	}
	states, err := logger.store.ListFindingStates("codeguard", "/repo", false, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].RuleID != "CG-EXEC-001" ||
		states[0].OccurrenceCount != 2 || states[0].LastScanID != second.ScanID {
		t.Fatalf("distinct finding lifecycle = %+v", states)
	}
	firstTransitions, err := logger.store.ListScanFindings(first.ScanID)
	if err != nil {
		t.Fatal(err)
	}
	secondTransitions, err := logger.store.ListScanFindings(second.ScanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstTransitions) != 1 || len(secondTransitions) != 0 {
		t.Fatalf("transition rows first/repeat = %d/%d, want 1/0",
			len(firstTransitions), len(secondTransitions))
	}
	events, err := logger.store.ListEvents(10)
	if err != nil || len(events) != 0 {
		t.Fatalf("standalone persistence generated runtime event history: count=%d err=%v",
			len(events), err)
	}

	// The dedicated method must not weaken the runtime producer contract:
	// LogScan still fails before persistence when the v8 runtime is detached.
	detached := result(base.Add(2 * time.Minute))
	if err := logger.LogScan(detached); err == nil ||
		!strings.Contains(err.Error(), "runtime is unavailable") {
		t.Fatalf("detached runtime LogScan error = %v", err)
	}
	counts, err = logger.store.GetCounts()
	if err != nil || counts.TotalScans != 2 {
		t.Fatalf("detached runtime changed forensic count = %d err=%v", counts.TotalScans, err)
	}
}
