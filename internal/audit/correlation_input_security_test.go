// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestListRecentFindingsInSessionFiltersAmplificationBeforeLimit(t *testing.T) {
	logger := newTestLogger(t)
	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	insert := func(scanID, occurrenceID, scannerName, ruleID, fingerprint string, tags []string, at time.Time) {
		t.Helper()
		if err := logger.store.InsertScanSummary(scanner.ScanSummaryParams{
			ScanID: scanID, Scanner: scannerName, Target: "codex:PostToolUse",
			Timestamp: at, FindingCount: 1, MaxSeverity: "HIGH",
			SessionID: "session", AgentInstanceID: "agent",
		}); err != nil {
			t.Fatalf("insert summary %s: %v", scanID, err)
		}
		if err := logger.store.InsertScanFindings(scanID, "codex:PostToolUse", []scanner.Finding{{
			FindingOccurrenceID: occurrenceID,
			Scanner:             scannerName, RuleID: ruleID, Category: "trust-exploit",
			Severity: scanner.SeverityHigh, Title: "Trust finding", Tags: tags,
			ContentFingerprint: fingerprint,
		}}, scanner.ScanFindingMeta{
			Timestamp: at, SessionID: "session", AgentInstanceID: "agent",
		}); err != nil {
			t.Fatalf("insert findings %s: %v", scanID, err)
		}
	}

	// Distinct Observe-mode findings remain eligible. Filtering and primitive
	// deduplication must happen before LIMIT so newer self-generated or repeated
	// rows cannot evict the older distinct finding from the window.
	insert("scan-observe", "finding-observe", "hook-rules", "TRUST-OBSERVE", "observe1", []string{"prompt-injection"}, base)
	insert("scan-repeat-one", "finding-repeat-one", "hook-rules", "TRUST-REPEAT", "repeat12", []string{"prompt-injection"}, base.Add(time.Second))
	insert("scan-repeat-two", "finding-repeat-two", "hook-rules", "TRUST-REPEAT", "repeat12", []string{"prompt-injection"}, base.Add(2*time.Second))
	insert("scan-detection", "finding-detection", "hook-rules", "TRUST-SOURCE", "source12", []string{"prompt-injection", "detection-only"}, base.Add(3*time.Second))
	insert("scan-correlation", "finding-correlation", "correlator", "CORR-TEST", "corr1234", []string{"correlation"}, base.Add(4*time.Second))

	rows, err := logger.store.ListRecentFindingsInSession("session", "agent", "", 2)
	if err != nil {
		t.Fatalf("ListRecentFindingsInSession: %v", err)
	}
	if len(rows) != 2 || rows[0].ID != "finding-repeat-one" || rows[1].ID != "finding-observe" ||
		rows[0].Scanner != "hook-rules" || rows[1].Scanner != "hook-rules" {
		t.Fatalf("eligible correlation rows=%#v, want earliest repeat plus distinct Observe finding", rows)
	}
	if len(rows[1].Tags) != 1 || rows[1].Tags[0] != "prompt-injection" {
		t.Fatalf("projected tags=%v, want prompt-injection", rows[1].Tags)
	}
}

func TestListRecentFindingsInSessionPreservesOriginalPrimitiveOrder(t *testing.T) {
	logger := newTestLogger(t)
	base := time.Date(2026, 8, 10, 12, 30, 0, 0, time.UTC)
	insert := func(scanID, occurrenceID, ruleID, fingerprint string, axis string, at time.Time) {
		t.Helper()
		if err := logger.store.InsertScanSummary(scanner.ScanSummaryParams{
			ScanID: scanID, Scanner: "hook-rules", Target: "codex:PostToolUse",
			Timestamp: at, FindingCount: 1, MaxSeverity: "HIGH",
			SessionID: "ordered-session", AgentInstanceID: "agent",
		}); err != nil {
			t.Fatalf("insert summary %s: %v", scanID, err)
		}
		if err := logger.store.InsertScanFindings(scanID, "codex:PostToolUse", []scanner.Finding{{
			FindingOccurrenceID: occurrenceID, Scanner: "hook-rules", RuleID: ruleID,
			Category: "general", Severity: scanner.SeverityHigh, Title: "Finding",
			ContentFingerprint: fingerprint, DataAxis: []string{axis},
		}}, scanner.ScanFindingMeta{
			Timestamp: at, SessionID: "ordered-session", AgentInstanceID: "agent",
		}); err != nil {
			t.Fatalf("insert finding %s: %v", scanID, err)
		}
	}

	insert("scan-ingress", "finding-ingress-original", "TRUST-SOURCE", "ingressfp", "ingress_untrusted", base)
	insert("scan-sensitive", "finding-sensitive", "SEC-VALUE", "secretfp", "sensitive_access", base.Add(time.Second))
	insert("scan-egress", "finding-egress", "C2-EXTERNAL", "egressfp", "egress_external", base.Add(2*time.Second))
	insert("scan-echo", "finding-ingress-echo", "TRUST-SOURCE", "ingressfp", "ingress_untrusted", base.Add(3*time.Second))

	rows, err := logger.store.ListRecentFindingsInSession("ordered-session", "agent", "", 3)
	if err != nil {
		t.Fatalf("ListRecentFindingsInSession: %v", err)
	}
	if len(rows) != 3 || rows[0].ID != "finding-egress" || rows[1].ID != "finding-sensitive" ||
		rows[2].ID != "finding-ingress-original" {
		t.Fatalf("dedup reordered original primitive: %#v", rows)
	}
}

func TestListRecentFindingsInSessionPartitionsLogicalAgentsInsideSharedInstance(t *testing.T) {
	logger := newTestLogger(t)
	base := time.Date(2026, 8, 10, 12, 40, 0, 0, time.UTC)
	insert := func(scanID, occurrenceID, logicalAgentID, axis string, at time.Time) {
		t.Helper()
		if err := logger.store.InsertScanSummary(scanner.ScanSummaryParams{
			ScanID: scanID, Scanner: "hook-rules", Target: "codex:PostToolUse",
			Timestamp: at, FindingCount: 1, MaxSeverity: "HIGH",
			SessionID: "shared-session", AgentInstanceID: "shared-instance", AgentID: logicalAgentID,
		}); err != nil {
			t.Fatalf("insert summary %s: %v", scanID, err)
		}
		if err := logger.store.InsertScanFindings(scanID, "codex:PostToolUse", []scanner.Finding{{
			FindingOccurrenceID: occurrenceID, Scanner: "hook-rules", RuleID: "RULE-" + occurrenceID,
			Category: "general", Severity: scanner.SeverityHigh, Title: "Finding",
			ContentFingerprint: occurrenceID + "-fp", DataAxis: []string{axis},
		}}, scanner.ScanFindingMeta{
			Timestamp: at, SessionID: "shared-session", AgentInstanceID: "shared-instance", AgentID: logicalAgentID,
		}); err != nil {
			t.Fatalf("insert finding %s: %v", scanID, err)
		}
	}

	insert("scan-agent-a-ingress", "agent-a-ingress", "agent-a", "ingress_untrusted", base)
	insert("scan-agent-a-sensitive", "agent-a-sensitive", "agent-a", "sensitive_access", base.Add(time.Second))
	insert("scan-agent-b-egress", "agent-b-egress", "agent-b", "egress_external", base.Add(2*time.Second))

	rows, err := logger.store.ListRecentFindingsInSession(
		"shared-session", "shared-instance", "agent-a", 10,
	)
	if err != nil {
		t.Fatalf("ListRecentFindingsInSession: %v", err)
	}
	if len(rows) != 2 || rows[0].ID != "agent-a-sensitive" || rows[1].ID != "agent-a-ingress" {
		t.Fatalf("agent-a partition contains cross-agent rows: %#v", rows)
	}
	for _, row := range rows {
		if row.AgentID != "agent-a" || row.AgentInstanceID != "shared-instance" {
			t.Fatalf("projected identity=%q/%q, want agent-a/shared-instance", row.AgentID, row.AgentInstanceID)
		}
	}
}

func TestListFiredCorrelationRuleIDsInSessionUsesSyntheticMetadataOnly(t *testing.T) {
	logger := newTestLogger(t)
	base := time.Date(2026, 8, 10, 12, 45, 0, 0, time.UTC)
	insert := func(scanID, scannerName, ruleID, sessionID, agentInstanceID, logicalAgentID string, at time.Time) {
		t.Helper()
		if err := logger.store.InsertScanSummary(scanner.ScanSummaryParams{
			ScanID: scanID, Scanner: scannerName, Target: "codex:PostToolUse",
			Timestamp: at, FindingCount: 1, MaxSeverity: "CRITICAL",
			SessionID: sessionID, AgentInstanceID: agentInstanceID, AgentID: logicalAgentID,
		}); err != nil {
			t.Fatalf("insert summary %s: %v", scanID, err)
		}
		if err := logger.store.InsertScanFindings(scanID, "codex:PostToolUse", []scanner.Finding{{
			FindingOccurrenceID: scanID + "-finding", Scanner: scannerName, RuleID: ruleID,
			Category: "correlation", Severity: scanner.SeverityCritical,
			Title: "Correlation metadata", Tags: []string{"correlation"},
		}}, scanner.ScanFindingMeta{
			Timestamp: at, SessionID: sessionID, AgentInstanceID: agentInstanceID, AgentID: logicalAgentID,
		}); err != nil {
			t.Fatalf("insert finding %s: %v", scanID, err)
		}
	}

	insert("scan-old-one", "correlator", "CORR-OLD", "ledger-session", "shared-instance", "agent-a", base)
	insert("scan-old-two", "CORRELATOR", "corr-old", "ledger-session", "shared-instance", "agent-a", base.Add(time.Second))
	insert("scan-wrong-scanner", "hook-rules", "CORR-NEW", "ledger-session", "shared-instance", "agent-a", base.Add(2*time.Second))
	insert("scan-wrong-session", "correlator", "CORR-NEW", "other-session", "shared-instance", "agent-a", base.Add(3*time.Second))
	insert("scan-other-agent", "correlator", "CORR-NEW", "ledger-session", "shared-instance", "agent-b", base.Add(4*time.Second))

	fired, err := logger.store.ListFiredCorrelationRuleIDsInSession(
		"ledger-session", "shared-instance", "agent-a", []string{"CORR-OLD", "CORR-NEW", "CORR-UNFIRED"},
	)
	if err != nil {
		t.Fatalf("ListFiredCorrelationRuleIDsInSession: %v", err)
	}
	if len(fired) != 1 || fired[0] != "CORR-OLD" {
		t.Fatalf("durable correlation ledger=%v, want only CORR-OLD", fired)
	}
	fired, err = logger.store.ListFiredCorrelationRuleIDsInSession(
		"ledger-session", "shared-instance", "agent-b", []string{"CORR-OLD", "CORR-NEW"},
	)
	if err != nil {
		t.Fatalf("ListFiredCorrelationRuleIDsInSession other agent: %v", err)
	}
	if len(fired) != 1 || fired[0] != "CORR-NEW" {
		t.Fatalf("other-agent durable ledger=%v, want only CORR-NEW", fired)
	}
}

func TestListRecentFindingsInSessionBoundsDuplicateOverscan(t *testing.T) {
	logger := newTestLogger(t)
	base := time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC)
	insert := func(index int, ruleID, fingerprint string, at time.Time) {
		t.Helper()
		scanID := fmt.Sprintf("scan-%d", index)
		if err := logger.store.InsertScanSummary(scanner.ScanSummaryParams{
			ScanID: scanID, Scanner: "hook-rules", Target: "codex:PostToolUse",
			Timestamp: at, FindingCount: 1, MaxSeverity: "HIGH",
			SessionID: "bounded-session", AgentInstanceID: "agent",
		}); err != nil {
			t.Fatalf("insert summary %d: %v", index, err)
		}
		if err := logger.store.InsertScanFindings(scanID, "codex:PostToolUse", []scanner.Finding{{
			FindingOccurrenceID: fmt.Sprintf("finding-%d", index),
			Scanner:             "hook-rules", RuleID: ruleID, Category: "trust-exploit",
			Severity: scanner.SeverityHigh, Title: "Trust finding",
			Tags: []string{"prompt-injection"}, ContentFingerprint: fingerprint,
		}}, scanner.ScanFindingMeta{
			Timestamp: at, SessionID: "bounded-session", AgentInstanceID: "agent",
		}); err != nil {
			t.Fatalf("insert finding %d: %v", index, err)
		}
	}

	insert(0, "TRUST-DISTINCT", "distinct", base)
	limit := 2
	for index := 1; index <= limit*correlationCandidateMultiplier; index++ {
		insert(index, "TRUST-REPEATED", "repeated", base.Add(time.Duration(index)*time.Second))
	}

	rows, err := logger.store.ListRecentFindingsInSession("bounded-session", "agent", "", limit)
	if err != nil {
		t.Fatalf("ListRecentFindingsInSession: %v", err)
	}
	// The overscan is deliberately finite. A flood larger than 8x the declared
	// window ages older distinct primitives out instead of causing an unbounded
	// full-session query; importantly, it still cannot create a synthetic chain.
	if len(rows) != 1 || rows[0].RuleID.String != "TRUST-REPEATED" {
		t.Fatalf("bounded overscan rows=%#v, want one deduplicated recent primitive", rows)
	}
}
