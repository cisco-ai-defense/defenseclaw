// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestBuildInspectScanResultPreservesFindingFacts(t *testing.T) {
	line := 12
	evaluationID, result := BuildInspectScanResult(InspectFindingSource{
		Scanner:    "hook-rules",
		Target:     "claudecode:PreToolUse",
		TargetType: "tool_call",
		Verdict:    "block",
		DurationMs: 2,
		Findings: []InspectFinding{
			{
				RuleID: "SECRET-AWS-AKIA", Title: "AWS access key", Severity: SeverityHigh,
				Description: "credential AKIAIOSFODNN7EXAMPLE", Confidence: 0.95,
				Evidence: "AKIAIOSFODNN7EXAMPLE", LineNumber: &line,
				Tags: []string{"secret"},
			},
			{
				RuleID: "PII-EMAIL", Title: "Email address", Severity: SeverityMedium,
				Description: "matched alice@example.com", Confidence: 0.7,
				Evidence: "alice@example.com",
			},
		},
	})
	if evaluationID == "" || result == nil || result.Scanner != "hook-rules" ||
		result.Target != "claudecode:PreToolUse" || result.TargetType != "tool_call" ||
		result.Verdict != "block" || result.Duration.Milliseconds() != 2 || len(result.Findings) != 2 {
		t.Fatalf("evaluation=%q result=%#v", evaluationID, result)
	}
	if result.Findings[0].RuleID != "SECRET-AWS-AKIA" || result.Findings[0].Description != "credential AKIAIOSFODNN7EXAMPLE" ||
		result.Findings[0].EvidenceSummary != "AKIAIOSFODNN7EXAMPLE" ||
		result.Findings[0].LineNumber == nil || *result.Findings[0].LineNumber != line ||
		result.Findings[0].Confidence != 0.95 {
		t.Fatalf("first finding = %#v", result.Findings[0])
	}
	if result.Findings[1].Description != "matched alice@example.com" {
		t.Fatalf("source evidence was transformed before routing: %#v", result.Findings[1])
	}
	if result.Findings[1].EvidenceSummary != "alice@example.com" {
		t.Fatalf("source evidence summary was lost before routing: %#v", result.Findings[1])
	}
}

func TestBuildInspectScanResultBoundsEvidenceSummaryWithoutChangingFingerprintSource(t *testing.T) {
	evidence := strings.Repeat("界", 2000)
	_, result := BuildInspectScanResult(InspectFindingSource{
		Scanner: "hook-rules", Target: "codex:PreToolUse",
		Findings: []InspectFinding{{RuleID: "TEST", Evidence: evidence}},
	})
	finding := result.Findings[0]
	if finding.EvidenceSummary == "" || len(finding.EvidenceSummary) > maxInspectEvidenceSummaryBytes ||
		!utf8.ValidString(finding.EvidenceSummary) {
		t.Fatalf("bounded evidence summary bytes=%d valid=%v", len(finding.EvidenceSummary), utf8.ValidString(finding.EvidenceSummary))
	}
	if finding.ContentFingerprint != evidenceFingerprint(evidence) {
		t.Fatalf("fingerprint=%q want hash of complete source excerpt", finding.ContentFingerprint)
	}
}

func TestBuildInspectScanResultGeneratesEvaluationID(t *testing.T) {
	evaluationID, result := BuildInspectScanResult(InspectFindingSource{
		Scanner: "guardrail-llm", Target: "model", Verdict: "allow",
	})
	if evaluationID == "" || len(evaluationID) < 8 || !strings.Contains(evaluationID, "-") {
		t.Fatalf("generated evaluation ID = %q", evaluationID)
	}
	if result.ScanID != "" {
		t.Fatalf("builder unexpectedly allocated persistence scan ID %q", result.ScanID)
	}
}

func TestBuildInspectScanResultUsesProvidedIdentifiers(t *testing.T) {
	const (
		evaluationID = "caller-supplied-1234"
		scanID       = "57ab7d45-1ac3-4afd-9b9f-b7b684d73995"
	)
	gotEvaluation, result := BuildInspectScanResult(InspectFindingSource{
		Scanner: "ai-defense", Target: "prompt", Verdict: "warn",
		EvaluationID: evaluationID, ScanID: scanID,
	})
	if gotEvaluation != evaluationID || result.ScanID != scanID {
		t.Fatalf("identifiers = %q/%q", gotEvaluation, result.ScanID)
	}
}

func TestTopRuleIDs(t *testing.T) {
	in := []InspectFinding{
		{RuleID: "A"}, {RuleID: "B"}, {RuleID: "A"}, {RuleID: ""},
		{RuleID: "C"}, {RuleID: "D"}, {RuleID: "E"}, {RuleID: "F"},
	}
	got := TopRuleIDs(in, 3)
	if strings.Join(got, ",") != "A,B,C" {
		t.Errorf("TopRuleIDs(_, 3) = %v", got)
	}
	if TopRuleIDs(in, 0) != nil {
		t.Error("TopRuleIDs with n=0 should return nil")
	}
}
