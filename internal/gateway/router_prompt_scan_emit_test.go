// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestGuardrailActionToScanVerdict(t *testing.T) {
	if got := guardrailActionToScanVerdict(guardrailActionAlert); got != "warn" {
		t.Fatalf("alert: got %q", got)
	}
	if got := guardrailActionToScanVerdict(guardrailActionBlock); got != "block" {
		t.Fatalf("block: got %q", got)
	}
	if got := guardrailActionToScanVerdict(guardrailActionAllow); got != "clean" {
		t.Fatalf("allow: got %q", got)
	}
}

func TestBuildSessionPromptScanResult(t *testing.T) {
	v := &ScanVerdict{
		Action:   "alert",
		Severity: "HIGH",
		Reason:   "matched: test",
		Findings: []string{"PATH-AWS-CREDS:aws path"},
		Scanner:  "local-pattern",
	}
	d := 12 * time.Millisecond
	res := buildSessionPromptScanResult(v, "msg-1", d)
	if res == nil {
		t.Fatal("nil result")
	}
	if res.Scanner != "local-pattern" {
		t.Fatalf("scanner: got %q", res.Scanner)
	}
	if res.Target != "message:msg-1" {
		t.Fatalf("target: got %q", res.Target)
	}
	if res.Duration != d {
		t.Fatalf("duration: got %v", res.Duration)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings len: %d", len(res.Findings))
	}
	if res.Findings[0].Severity != scanner.SeverityHigh {
		t.Fatalf("finding severity: got %s", res.Findings[0].Severity)
	}
}

func TestBuildSessionPromptScanResult_FallbackFinding(t *testing.T) {
	v := &ScanVerdict{
		Action:   "block",
		Severity: "CRITICAL",
		Reason:   "synthetic",
		Findings: nil,
	}
	res := buildSessionPromptScanResult(v, "m2", time.Millisecond)
	if res == nil || len(res.Findings) != 1 {
		t.Fatalf("got %+v", res)
	}
	if res.Findings[0].RuleID != "session-prompt" {
		t.Fatalf("rule id: %q", res.Findings[0].RuleID)
	}
}
