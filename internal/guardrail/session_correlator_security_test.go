// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

type staticSessionFindingReader struct {
	rows         []SessionFindingRow
	firedRuleIDs []string
}

type partitionedSessionFindingReader struct {
	rows             []SessionFindingRow
	firedByPartition map[string][]string
}

func (r partitionedSessionFindingReader) ListRecentFindingsInSession(_, _, _ string, _ int) ([]SessionFindingRow, error) {
	return append([]SessionFindingRow(nil), r.rows...), nil
}

func (r partitionedSessionFindingReader) ListFiredCorrelationRuleIDsInSession(
	sessionID, agentInstanceID, agentID string,
	candidateRuleIDs []string,
) ([]string, error) {
	key := sessionID + "\x00" + agentInstanceID + "\x00" + agentID
	wanted := make(map[string]struct{}, len(candidateRuleIDs))
	for _, ruleID := range candidateRuleIDs {
		wanted[strings.ToLower(strings.TrimSpace(ruleID))] = struct{}{}
	}
	var out []string
	for _, ruleID := range r.firedByPartition[key] {
		if _, ok := wanted[strings.ToLower(strings.TrimSpace(ruleID))]; ok {
			out = append(out, ruleID)
		}
	}
	return out, nil
}

func (r staticSessionFindingReader) ListRecentFindingsInSession(_, _, _ string, _ int) ([]SessionFindingRow, error) {
	return append([]SessionFindingRow(nil), r.rows...), nil
}

func (r staticSessionFindingReader) ListFiredCorrelationRuleIDsInSession(
	_, _, _ string, candidateRuleIDs []string,
) ([]string, error) {
	wanted := make(map[string]struct{}, len(candidateRuleIDs))
	for _, ruleID := range candidateRuleIDs {
		wanted[strings.ToLower(strings.TrimSpace(ruleID))] = struct{}{}
	}
	var out []string
	for _, ruleID := range r.firedRuleIDs {
		if _, ok := wanted[strings.ToLower(strings.TrimSpace(ruleID))]; ok {
			out = append(out, ruleID)
		}
	}
	return out, nil
}

type recordingCorrelationPersistence struct {
	summaries []scanner.ScanSummaryParams
	findings  [][]scanner.Finding
}

func (p *recordingCorrelationPersistence) InsertScanSummary(summary scanner.ScanSummaryParams) error {
	p.summaries = append(p.summaries, summary)
	return nil
}

func (p *recordingCorrelationPersistence) InsertScanFindings(_ string, _ string, findings []scanner.Finding, _ scanner.ScanFindingMeta) error {
	p.findings = append(p.findings, append([]scanner.Finding(nil), findings...))
	return nil
}

func TestSessionCorrelatorRejectsSelfObservationAmplificationInputs(t *testing.T) {
	pattern := CorrelationPattern{
		ID: "ESCALATION", WindowEvents: 10, SeverityOnMatch: "CRITICAL",
		Sequence: []SequenceClause{{Severity: "MEDIUM"}, {Severity: "HIGH"}, {Severity: "HIGH"}},
	}
	base := []SessionFindingRow{
		correlationTestRow("high-real", "TRUST-A", "trust-exploit", "HIGH", "fp-high", "hook-rules", nil),
		correlationTestRow("medium-real", "TRUST-B", "trust-exploit", "MEDIUM", "fp-medium", "hook-rules", nil),
	}
	tests := []struct {
		name  string
		extra SessionFindingRow
	}{
		{
			name:  "same finding displayed twice",
			extra: correlationTestRow("high-reread", "TRUST-A", "trust-exploit", "HIGH", "fp-high", "hook-rules", nil),
		},
		{
			name:  "detection-only source literal",
			extra: correlationTestRow("high-source", "TRUST-C", "trust-exploit", "HIGH", "fp-source", "hook-rules", []string{"prompt-injection", "detection-only"}),
		},
		{
			name:  "prior correlator output",
			extra: correlationTestRow("high-synthetic", "CORR-ESCALATION", "correlation", "HIGH", "fp-corr", "correlator", []string{"correlation"}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows := append([]SessionFindingRow{tc.extra}, base...)
			persisted := &recordingCorrelationPersistence{}
			correlator := NewSessionCorrelator(staticSessionFindingReader{rows: rows}, []CorrelationPattern{pattern})
			if err := correlator.RunForSession(
				context.Background(), "session", "agent", persisted, "codex:PostToolUse", scanner.ScanFindingMeta{},
			); err != nil {
				t.Fatalf("RunForSession: %v", err)
			}
			if len(persisted.summaries) != 0 || len(persisted.findings) != 0 {
				t.Fatalf("amplified input created synthetic finding: summaries=%#v findings=%#v", persisted.summaries, persisted.findings)
			}
		})
	}
}

func TestSessionCorrelatorPreservesDistinctEnforcementEligibleFindings(t *testing.T) {
	pattern := CorrelationPattern{
		ID: "ESCALATION", WindowEvents: 10, SeverityOnMatch: "CRITICAL",
		Sequence: []SequenceClause{{Severity: "MEDIUM"}, {Severity: "HIGH"}, {Severity: "HIGH"}},
	}
	// Observe mode changes the action taken after evaluation; it does not add
	// the detection-only provenance tag. These are distinct real primitives and
	// must therefore remain eligible for correlation while Observe is active.
	rows := []SessionFindingRow{
		correlationTestRow("high-two", "TRUST-C", "trust-exploit", "HIGH", "fp-two", "hook-rules", []string{"prompt-injection"}),
		correlationTestRow("high-one", "TRUST-A", "trust-exploit", "HIGH", "fp-one", "hook-rules", []string{"prompt-injection"}),
		correlationTestRow("medium", "TRUST-B", "trust-exploit", "MEDIUM", "fp-medium", "hook-rules", []string{"prompt-injection"}),
	}
	persisted := &recordingCorrelationPersistence{}
	correlator := NewSessionCorrelator(staticSessionFindingReader{rows: rows}, []CorrelationPattern{pattern})
	if err := correlator.RunForSession(
		context.Background(), "observe-session", "agent", persisted, "codex:PostToolUse", scanner.ScanFindingMeta{},
	); err != nil {
		t.Fatalf("RunForSession: %v", err)
	}
	if len(persisted.summaries) != 1 || persisted.summaries[0].Scanner != "correlator" ||
		len(persisted.findings) != 1 || len(persisted.findings[0]) != 1 ||
		persisted.findings[0][0].RuleID != "CORR-ESCALATION" {
		t.Fatalf("distinct findings were not correlated: summaries=%#v findings=%#v", persisted.summaries, persisted.findings)
	}
}

func TestSessionCorrelatorPreservesFingerprintLinksAcrossDistinctRules(t *testing.T) {
	pattern := CorrelationPattern{
		ID: "DIRECT-EXFIL", WindowEvents: 10, SeverityOnMatch: "CRITICAL",
		FingerprintLink: []PatternClause{{Axis: AxisSensitiveAccess}, {Axis: AxisEgressExternal}},
	}
	rows := []SessionFindingRow{
		correlationTestRowWithAxis("egress", "C2-EXTERNAL", "network", "HIGH", "shared123", "hook-rules", AxisEgressExternal),
		correlationTestRowWithAxis("sensitive", "SEC-VALUE", "secret", "HIGH", "shared123", "hook-rules", AxisSensitiveAccess),
	}
	persisted := &recordingCorrelationPersistence{}
	correlator := NewSessionCorrelator(staticSessionFindingReader{rows: rows}, []CorrelationPattern{pattern})
	if err := correlator.RunForSession(
		context.Background(), "fingerprint-session", "agent", persisted, "codex:PostToolUse", scanner.ScanFindingMeta{},
	); err != nil {
		t.Fatalf("RunForSession: %v", err)
	}
	if len(persisted.findings) != 1 || len(persisted.findings[0]) != 1 ||
		persisted.findings[0][0].RuleID != "CORR-DIRECT-EXFIL" {
		t.Fatalf("distinct fingerprint link did not correlate: %#v", persisted.findings)
	}
}

func TestSessionCorrelatorKeepsEarliestPrimitiveForOrderedPatterns(t *testing.T) {
	pattern := CorrelationPattern{
		ID: "LETHAL-ORDER", WindowEvents: 10, SeverityOnMatch: "CRITICAL", Ordered: true,
		AllOf: []PatternClause{
			{Axis: AxisIngressUntrusted},
			{Axis: AxisSensitiveAccess},
			{Axis: AxisEgressExternal},
		},
	}
	// Newest-first input. The final ingress row is a re-read of the first
	// primitive. Keeping that newest echo would move ingress after egress and
	// erase the real ordered chain.
	rows := []SessionFindingRow{
		correlationTestRowWithAxis("ingress-echo", "TRUST-SOURCE", "trust-exploit", "HIGH", "ingressfp", "hook-rules", AxisIngressUntrusted),
		correlationTestRowWithAxis("egress", "C2-EXTERNAL", "network", "HIGH", "egressfp", "hook-rules", AxisEgressExternal),
		correlationTestRowWithAxis("sensitive", "SEC-VALUE", "secret", "HIGH", "secretfp", "hook-rules", AxisSensitiveAccess),
		correlationTestRowWithAxis("ingress-original", "TRUST-SOURCE", "trust-exploit", "HIGH", "ingressfp", "hook-rules", AxisIngressUntrusted),
	}
	for index := range rows {
		rows[index].AgentInstanceID = "shared-instance"
		rows[index].AgentID = "logical-agent"
	}
	persisted := &recordingCorrelationPersistence{}
	correlator := NewSessionCorrelator(staticSessionFindingReader{rows: rows}, []CorrelationPattern{pattern})
	if err := correlator.RunForSession(
		context.Background(), "ordered-session", "shared-instance", persisted, "codex:PostToolUse",
		scanner.ScanFindingMeta{AgentID: "logical-agent"},
	); err != nil {
		t.Fatalf("RunForSession: %v", err)
	}
	if len(persisted.findings) != 1 || len(persisted.findings[0]) != 1 ||
		persisted.findings[0][0].RuleID != "CORR-LETHAL-ORDER" {
		t.Fatalf("ordered chain was erased by its later echo: %#v", persisted.findings)
	}
}

func TestSessionCorrelatorDoesNotCombineAgentsInSharedSessionInstance(t *testing.T) {
	pattern := CorrelationPattern{
		ID: "LETHAL-ORDER", WindowEvents: 10, SeverityOnMatch: "CRITICAL", Ordered: true,
		AllOf: []PatternClause{
			{Axis: AxisIngressUntrusted},
			{Axis: AxisSensitiveAccess},
			{Axis: AxisEgressExternal},
		},
	}
	rows := []SessionFindingRow{
		correlationTestRowWithAxis("other-egress", "C2-EXTERNAL", "network", "CRITICAL", "egressfp", "hook-rules", AxisEgressExternal),
		correlationTestRowWithAxis("current-sensitive", "SEC-VALUE", "secret", "HIGH", "secretfp", "hook-rules", AxisSensitiveAccess),
		correlationTestRowWithAxis("current-ingress", "TRUST-SOURCE", "trust-exploit", "HIGH", "ingressfp", "hook-rules", AxisIngressUntrusted),
	}
	for index := range rows {
		rows[index].AgentInstanceID = "shared-instance"
		rows[index].AgentID = "agent-a"
	}
	rows[0].AgentID = "agent-b"

	persisted := &recordingCorrelationPersistence{}
	correlator := NewSessionCorrelator(staticSessionFindingReader{rows: rows}, []CorrelationPattern{pattern})
	if err := correlator.RunForSession(
		context.Background(), "shared-session", "shared-instance", persisted, "codex:PostToolUse",
		scanner.ScanFindingMeta{AgentID: "agent-a"},
	); err != nil {
		t.Fatalf("RunForSession: %v", err)
	}
	if len(persisted.summaries) != 0 || len(persisted.findings) != 0 {
		t.Fatalf("cross-agent primitives created a synthetic chain: summaries=%#v findings=%#v", persisted.summaries, persisted.findings)
	}
}

func TestSessionCorrelatorCorrelatesOrderedPrimitivesForOneAgent(t *testing.T) {
	pattern := CorrelationPattern{
		ID: "LETHAL-ORDER", WindowEvents: 10, SeverityOnMatch: "CRITICAL", Ordered: true,
		AllOf: []PatternClause{
			{Axis: AxisIngressUntrusted},
			{Axis: AxisSensitiveAccess},
			{Axis: AxisEgressExternal},
		},
	}
	rows := []SessionFindingRow{
		correlationTestRowWithAxis("egress", "C2-EXTERNAL", "network", "CRITICAL", "egressfp", "hook-rules", AxisEgressExternal),
		correlationTestRowWithAxis("sensitive", "SEC-VALUE", "secret", "HIGH", "secretfp", "hook-rules", AxisSensitiveAccess),
		correlationTestRowWithAxis("ingress", "TRUST-SOURCE", "trust-exploit", "HIGH", "ingressfp", "hook-rules", AxisIngressUntrusted),
	}
	for index := range rows {
		rows[index].AgentInstanceID = "shared-instance"
		rows[index].AgentID = "agent-a"
	}

	persisted := &recordingCorrelationPersistence{}
	correlator := NewSessionCorrelator(staticSessionFindingReader{rows: rows}, []CorrelationPattern{pattern})
	if err := correlator.RunForSession(
		context.Background(), "shared-session", "shared-instance", persisted, "codex:PostToolUse",
		scanner.ScanFindingMeta{AgentID: "agent-a"},
	); err != nil {
		t.Fatalf("RunForSession: %v", err)
	}
	if len(persisted.findings) != 1 || len(persisted.findings[0]) != 1 ||
		persisted.findings[0][0].RuleID != "CORR-LETHAL-ORDER" {
		t.Fatalf("one-agent ordered primitives did not correlate: %#v", persisted.findings)
	}
	if len(persisted.summaries) != 1 || persisted.summaries[0].AgentID != "agent-a" ||
		persisted.summaries[0].AgentInstanceID != "shared-instance" {
		t.Fatalf("synthetic summary lost agent partition: %#v", persisted.summaries)
	}
}

func TestSessionCorrelatorFallsBackToAgentIDOnlyWhenInstanceMissing(t *testing.T) {
	pattern := CorrelationPattern{
		ID: "PAIR", WindowEvents: 10, SeverityOnMatch: "CRITICAL",
		Sequence: []SequenceClause{{Severity: "MEDIUM"}, {Severity: "HIGH"}},
	}
	rows := []SessionFindingRow{
		correlationTestRow("high", "TRUST-HIGH", "trust-exploit", "HIGH", "highfp", "hook-rules", nil),
		correlationTestRow("medium", "TRUST-MEDIUM", "trust-exploit", "MEDIUM", "mediumfp", "hook-rules", nil),
	}
	for index := range rows {
		rows[index].AgentInstanceID = ""
		rows[index].AgentID = "agent-fallback"
	}

	persisted := &recordingCorrelationPersistence{}
	correlator := NewSessionCorrelator(staticSessionFindingReader{rows: rows}, []CorrelationPattern{pattern})
	if err := correlator.RunForSession(
		context.Background(), "fallback-session", "", persisted, "codex:PostToolUse",
		scanner.ScanFindingMeta{AgentID: "agent-fallback"},
	); err != nil {
		t.Fatalf("RunForSession: %v", err)
	}
	if len(persisted.findings) != 1 || len(persisted.findings[0]) != 1 {
		t.Fatalf("agent-id fallback did not correlate identity-matched rows: %#v", persisted.findings)
	}
}

func TestSessionCorrelatorUsesPersistedFiringLedgerAfterRestart(t *testing.T) {
	oldPattern := CorrelationPattern{
		ID: "ALREADY-FIRED", WindowEvents: 10, SeverityOnMatch: "CRITICAL",
		Sequence: []SequenceClause{{Severity: "MEDIUM"}, {Severity: "HIGH"}, {Severity: "HIGH"}},
	}
	newPattern := oldPattern
	newPattern.ID = "NEW-PATTERN"
	rows := []SessionFindingRow{
		correlationTestRow("detection-trigger", "TRUST-SOURCE", "trust-exploit", "HIGH", "triggerfp", "hook-rules", []string{scanner.FindingTagDetectionOnly}),
		correlationTestRow("high-two", "TRUST-C", "trust-exploit", "HIGH", "hightwo", "hook-rules", nil),
		correlationTestRow("high-one", "TRUST-B", "trust-exploit", "HIGH", "highone", "hook-rules", nil),
		correlationTestRow("medium", "TRUST-A", "trust-exploit", "MEDIUM", "mediumfp", "hook-rules", nil),
		correlationTestRow("prior-correlation", "CORR-ALREADY-FIRED", "correlation", "CRITICAL", "corrfp", "correlator", []string{"correlation"}),
	}
	reader := staticSessionFindingReader{
		rows: rows, firedRuleIDs: []string{"CORR-ALREADY-FIRED"},
	}

	// A fresh correlator has an empty in-memory map, simulating a restart. The
	// persisted CORR rule identity suppresses replay from unchanged primitives.
	persisted := &recordingCorrelationPersistence{}
	restarted := NewSessionCorrelator(reader, []CorrelationPattern{oldPattern})
	if err := restarted.RunForSession(
		context.Background(), "restart-session", "agent", persisted, "codex:PostToolUse", scanner.ScanFindingMeta{},
	); err != nil {
		t.Fatalf("RunForSession after restart: %v", err)
	}
	if len(persisted.summaries) != 0 || len(persisted.findings) != 0 {
		t.Fatalf("restart replayed durable pattern: summaries=%#v findings=%#v", persisted.summaries, persisted.findings)
	}

	// The ledger is pattern-specific: a genuinely new pattern matching the same
	// real primitives must still be allowed to fire once.
	persisted = &recordingCorrelationPersistence{}
	restarted = NewSessionCorrelator(reader, []CorrelationPattern{oldPattern, newPattern})
	if err := restarted.RunForSession(
		context.Background(), "restart-session", "agent", persisted, "codex:PostToolUse", scanner.ScanFindingMeta{},
	); err != nil {
		t.Fatalf("RunForSession with new pattern: %v", err)
	}
	if len(persisted.findings) != 1 || len(persisted.findings[0]) != 1 ||
		persisted.findings[0][0].RuleID != "CORR-NEW-PATTERN" {
		t.Fatalf("new unfired pattern was not isolated: %#v", persisted.findings)
	}
}

func TestSessionCorrelatorPersistedLedgerIsAgentPartitionedAfterRestart(t *testing.T) {
	pattern := CorrelationPattern{
		ID: "PAIR", WindowEvents: 10, SeverityOnMatch: "CRITICAL",
		Sequence: []SequenceClause{{Severity: "MEDIUM"}, {Severity: "HIGH"}},
	}
	rows := []SessionFindingRow{
		correlationTestRow("high", "TRUST-HIGH", "trust-exploit", "HIGH", "highfp", "hook-rules", nil),
		correlationTestRow("medium", "TRUST-MEDIUM", "trust-exploit", "MEDIUM", "mediumfp", "hook-rules", nil),
	}
	for index := range rows {
		rows[index].AgentInstanceID = "shared-instance"
		rows[index].AgentID = "agent-a"
	}
	partitionKey := func(agentID string) string {
		return "shared-session\x00shared-instance\x00" + agentID
	}

	// A persisted firing for another logical agent in the same session and
	// instance must not suppress this agent's first legitimate firing.
	reader := partitionedSessionFindingReader{
		rows: rows,
		firedByPartition: map[string][]string{
			partitionKey("agent-b"): {"CORR-PAIR"},
		},
	}
	persisted := &recordingCorrelationPersistence{}
	restarted := NewSessionCorrelator(reader, []CorrelationPattern{pattern})
	if err := restarted.RunForSession(
		context.Background(), "shared-session", "shared-instance", persisted, "codex:PostToolUse",
		scanner.ScanFindingMeta{AgentID: "agent-a"},
	); err != nil {
		t.Fatalf("RunForSession with other-agent ledger: %v", err)
	}
	if len(persisted.findings) != 1 || len(persisted.findings[0]) != 1 {
		t.Fatalf("other agent's ledger suppressed current agent: %#v", persisted.findings)
	}

	// A second fresh correlator simulates another restart. Once this exact
	// agent partition has persisted the rule, unchanged primitives stay quiet.
	reader.firedByPartition[partitionKey("agent-a")] = []string{"CORR-PAIR"}
	persisted = &recordingCorrelationPersistence{}
	restarted = NewSessionCorrelator(reader, []CorrelationPattern{pattern})
	if err := restarted.RunForSession(
		context.Background(), "shared-session", "shared-instance", persisted, "codex:PostToolUse",
		scanner.ScanFindingMeta{AgentID: "agent-a"},
	); err != nil {
		t.Fatalf("RunForSession with current-agent ledger: %v", err)
	}
	if len(persisted.summaries) != 0 || len(persisted.findings) != 0 {
		t.Fatalf("restart replayed current agent's durable firing: summaries=%#v findings=%#v", persisted.summaries, persisted.findings)
	}
}

func correlationTestRow(id, ruleID, category, severity, fingerprint, scannerName string, tags []string) SessionFindingRow {
	return SessionFindingRow{
		ID: id, AgentInstanceID: "agent", RuleID: sql.NullString{String: ruleID, Valid: true},
		Category: sql.NullString{String: category, Valid: true}, Severity: severity,
		ContentFingerprint: sql.NullString{String: fingerprint, Valid: fingerprint != ""},
		Scanner:            scannerName, Tags: append([]string(nil), tags...),
	}
}

func correlationTestRowWithAxis(id, ruleID, category, severity, fingerprint, scannerName string, axis DataAxis) SessionFindingRow {
	row := correlationTestRow(id, ruleID, category, severity, fingerprint, scannerName, nil)
	row.DataAxis = sql.NullString{String: `["` + string(axis) + `"]`, Valid: true}
	return row
}
