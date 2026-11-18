// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestTopRuleIDsAndNamesBoundsEachDisplayName(t *testing.T) {
	longName := strings.Repeat("a", 255) + "é" + strings.Repeat("b", 32)
	ids, names := topRuleIDsAndNames([]scanner.InspectFinding{{
		RuleID: "CISCO-CUSTOM-1",
		Title:  longName,
	}}, 8)

	if len(ids) != 1 || ids[0] != "CISCO-CUSTOM-1" {
		t.Fatalf("rule IDs = %v, want unchanged custom ID", ids)
	}
	if len(names) != 1 || len(names[0]) > 256 || !utf8.ValidString(names[0]) {
		t.Fatalf("rule names = %q, want one valid UTF-8 value bounded to 256 bytes", names)
	}
	if names[0] != strings.Repeat("a", 255) {
		t.Fatalf("bounded rule name = %q, want truncation before split rune", names[0])
	}
}

// TestEmitInspectVerdictFindings_ZeroFindingsStillCountsAsScan pins
// the fix for the PR-579 security review finding that
// managed-enterprise hook inspections which allow with zero findings
// undercount `TotalScans`. Before the fix, `emitInspectVerdictFindings`
// early-returned when `len(verdict.DetailedFindings) == 0`, so an
// AID allow/no-findings hook inspection ran a scan but no
// `scan_results` row was written — the IPC `TotalScans` counter
// stayed frozen even as inspections happened.
//
// After the fix the function still returns on nil verdict (nothing
// scanned) but a non-nil verdict with an empty DetailedFindings
// slice flows through to `scanner.EmitInspectFindings`, which emits
// a scan_results row with finding_count=0. The audit-store's
// TotalScans counter then reflects every inspection.
func TestEmitInspectVerdictFindings_ZeroFindingsStillCountsAsScan(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	api := &APIServer{store: store, logger: logger}

	before, err := store.GetCounts()
	if err != nil {
		t.Fatalf("GetCounts baseline: %v", err)
	}
	if before.TotalScans != 0 {
		t.Fatalf("baseline TotalScans = %d, want 0 on a fresh store", before.TotalScans)
	}

	// AID allow-with-no-findings: the verdict is non-nil (a scan
	// happened) but carries no DetailedFindings (nothing flagged).
	// managedAIDOnly path returns exactly this shape.
	verdict := &ToolInspectVerdict{
		Action:           "allow",
		Severity:         "NONE",
		Findings:         []string{},
		DetailedFindings: nil,
	}
	_ = api.emitInspectVerdictFindings(context.Background(),
		"hook-rules", "claudecode:PreToolUse", "tool_call",
		verdict, 5*time.Millisecond, "emit_hook_findings")

	after, err := store.GetCounts()
	if err != nil {
		t.Fatalf("GetCounts after emit: %v", err)
	}
	if after.TotalScans != 1 {
		t.Fatalf("TotalScans = %d, want 1 (zero-finding hook inspection must still count)", after.TotalScans)
	}
	// And no alert-severity row was implicitly created — the alerts
	// counter must stay at zero for an allow verdict.
	if after.Alerts != 0 {
		t.Fatalf("Alerts = %d, want 0 (allow verdict must not raise an alert)", after.Alerts)
	}
}

// TestEmitInspectVerdictFindings_NilVerdictSkipped covers the guard
// that stayed: a nil verdict means "no inspection to record", not
// "inspection with zero findings". The counter must NOT increment.
func TestEmitInspectVerdictFindings_NilVerdictSkipped(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	api := &APIServer{store: store, logger: logger}

	_ = api.emitInspectVerdictFindings(context.Background(),
		"hook-rules", "claudecode:PreToolUse", "tool_call",
		nil, 5*time.Millisecond, "emit_hook_findings")

	after, err := store.GetCounts()
	if err != nil {
		t.Fatalf("GetCounts: %v", err)
	}
	if after.TotalScans != 0 {
		t.Fatalf("TotalScans = %d, want 0 (nil verdict = no inspection)", after.TotalScans)
	}
}
