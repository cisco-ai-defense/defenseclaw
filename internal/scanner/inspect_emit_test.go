// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

func TestEmitInspectFindings_FansOutPerFindingEvent(t *testing.T) {
	var emitted []gatewaylog.Event
	w, err := gatewaylog.New(gatewaylog.Config{})
	if err != nil {
		t.Fatal(err)
	}
	w.WithFanout(func(e gatewaylog.Event) { emitted = append(emitted, e) })

	tel := &mockTel{}
	line := 12
	evalID, scanID, err := EmitInspectFindings(context.Background(), w, nil, tel,
		InspectFindingSource{
			Scanner:    "hook-rules",
			Target:     "claudecode:PreToolUse",
			TargetType: "tool_call",
			Verdict:    "block",
			DurationMs: 2,
			Findings: []InspectFinding{
				{
					RuleID:     "SECRET-AWS-AKIA",
					Title:      "AWS access key",
					Severity:   SeverityHigh,
					Confidence: 0.95,
					Evidence:   "AKIAIOSFODNN7EXAMPLE",
					LineNumber: &line,
					Tags:       []string{"secret"},
				},
				{
					RuleID:     "PII-EMAIL",
					Title:      "Email address",
					Severity:   SeverityMedium,
					Confidence: 0.7,
					Evidence:   "alice@example.com",
				},
			},
		},
		AgentIdentity{
			AgentID:         "agent-1",
			AgentInstanceID: "instance-1",
			SessionID:       "session-1",
		},
	)
	if err != nil {
		t.Fatalf("EmitInspectFindings: %v", err)
	}
	if evalID == "" || scanID == "" {
		t.Fatalf("expected non-empty evaluation_id and scan_id, got %q / %q", evalID, scanID)
	}

	var scanEvent *gatewaylog.Event
	var findingEvents []*gatewaylog.Event
	for i := range emitted {
		switch emitted[i].EventType {
		case gatewaylog.EventScan:
			scanEvent = &emitted[i]
		case gatewaylog.EventScanFinding:
			findingEvents = append(findingEvents, &emitted[i])
		}
	}
	if scanEvent == nil {
		t.Fatalf("missing EventScan; got %d emitted events", len(emitted))
	}
	if scanEvent.Scan == nil {
		t.Fatal("scan event missing Scan payload")
	}
	if scanEvent.Scan.Scanner != "hook-rules" {
		t.Errorf("scan.scanner = %q, want hook-rules", scanEvent.Scan.Scanner)
	}
	if scanEvent.Scan.EvaluationID != evalID {
		t.Errorf("scan.evaluation_id = %q, want %q", scanEvent.Scan.EvaluationID, evalID)
	}
	if len(findingEvents) != 2 {
		t.Fatalf("expected 2 EventScanFinding rows, got %d", len(findingEvents))
	}
	for _, ev := range findingEvents {
		if ev.ScanFinding == nil {
			t.Fatal("finding event missing payload")
		}
		if ev.ScanFinding.EvaluationID != evalID {
			t.Errorf("scan_finding.evaluation_id = %q, want %q", ev.ScanFinding.EvaluationID, evalID)
		}
		if ev.ScanFinding.Scanner != "hook-rules" {
			t.Errorf("scan_finding.scanner = %q, want hook-rules", ev.ScanFinding.Scanner)
		}
		if ev.ScanFinding.ScanID != scanID {
			t.Errorf("scan_finding.scan_id = %q, want %q", ev.ScanFinding.ScanID, scanID)
		}
		if ev.ScanFinding.RuleID == "" {
			t.Error("scan_finding.rule_id is empty")
		}
		if ev.ScanFinding.Confidence <= 0 || ev.ScanFinding.Confidence > 1 {
			t.Errorf("scan_finding.confidence = %v, want in (0,1]", ev.ScanFinding.Confidence)
		}
	}

	if len(tel.byRule) != 2 {
		t.Errorf("RecordScanFindingByRule called %d times, want 2", len(tel.byRule))
	}
	for _, row := range tel.byRule {
		if row[0] != "hook-rules" {
			t.Errorf("metric scanner label = %q, want hook-rules", row[0])
		}
		if row[1] == "" {
			t.Errorf("metric rule_id label is empty: %+v", row)
		}
	}
}

func TestEmitInspectFindings_EmptyFindingsStillEmitsScanRollup(t *testing.T) {
	var emitted []gatewaylog.Event
	w, err := gatewaylog.New(gatewaylog.Config{})
	if err != nil {
		t.Fatal(err)
	}
	w.WithFanout(func(e gatewaylog.Event) { emitted = append(emitted, e) })

	evalID, scanID, err := EmitInspectFindings(context.Background(), w, nil, nil,
		InspectFindingSource{
			Scanner:    "inspect-http",
			Target:     "POST /api/v1/inspect/request",
			TargetType: "prompt",
			Verdict:    "clean",
			DurationMs: 1,
		},
		AgentIdentity{},
	)
	if err != nil {
		t.Fatalf("EmitInspectFindings: %v", err)
	}
	if evalID == "" || scanID == "" {
		t.Fatal("expected non-empty ids even for empty findings")
	}
	var sawScan bool
	for _, ev := range emitted {
		if ev.EventType == gatewaylog.EventScanFinding {
			t.Errorf("unexpected EventScanFinding for empty source")
		}
		if ev.EventType == gatewaylog.EventScan {
			sawScan = true
			if ev.Scan == nil || ev.Scan.EvaluationID != evalID {
				t.Errorf("scan event missing evaluation_id; got %+v", ev.Scan)
			}
		}
	}
	if !sawScan {
		t.Fatal("expected an EventScan roll-up even with zero findings")
	}
}

func TestEmitInspectFindings_GeneratesEvaluationIDWhenEmpty(t *testing.T) {
	evalID, _, err := EmitInspectFindings(context.Background(), nil, nil, nil,
		InspectFindingSource{Scanner: "guardrail-llm", Target: "model", Verdict: "allow"},
		AgentIdentity{},
	)
	if err != nil {
		t.Fatalf("EmitInspectFindings: %v", err)
	}
	if evalID == "" {
		t.Fatal("expected generated evaluation_id")
	}
	if len(evalID) < 8 || !strings.Contains(evalID, "-") {
		t.Errorf("evaluation_id %q does not look like a uuid", evalID)
	}
}

func TestEmitInspectFindings_UsesProvidedEvaluationID(t *testing.T) {
	evalID, _, err := EmitInspectFindings(context.Background(), nil, nil, nil,
		InspectFindingSource{
			Scanner:      "ai-defense",
			Target:       "prompt",
			Verdict:      "warn",
			EvaluationID: "caller-supplied-1234",
		},
		AgentIdentity{},
	)
	if err != nil {
		t.Fatalf("EmitInspectFindings: %v", err)
	}
	if evalID != "caller-supplied-1234" {
		t.Errorf("EmitInspectFindings clobbered caller evaluation_id; got %q", evalID)
	}
}

func TestTopRuleIDs(t *testing.T) {
	in := []InspectFinding{
		{RuleID: "A"},
		{RuleID: "B"},
		{RuleID: "A"}, // dedup
		{RuleID: ""},  // skip
		{RuleID: "C"},
		{RuleID: "D"},
		{RuleID: "E"},
		{RuleID: "F"},
	}
	got := TopRuleIDs(in, 3)
	want := []string{"A", "B", "C"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("TopRuleIDs(_, 3) = %v, want %v", got, want)
	}
	if TopRuleIDs(in, 0) != nil {
		t.Error("TopRuleIDs with n=0 should return nil")
	}
}
