// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEmitScanResultAllocatesSharedCanonicalIdentifiers(t *testing.T) {
	result := &ScanResult{
		Scanner: "skill-scanner", Target: "target", Timestamp: time.Now().UTC(),
		Findings: []Finding{
			{ID: "a", Severity: SeverityHigh, Title: "one", Scanner: "skill-scanner"},
			{ID: "b", Severity: SeverityLow, Title: "two", Scanner: "skill-scanner"},
		},
		Duration: time.Second,
	}
	scanID, err := EmitScanResult(context.Background(), nil, result, AgentIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	if scanID == "" || result.ScanID != scanID {
		t.Fatalf("result scan ID = %q, returned %q", result.ScanID, scanID)
	}
	seen := map[string]bool{}
	for index := range result.Findings {
		finding := result.Findings[index]
		if finding.FindingOccurrenceID == "" || seen[finding.FindingOccurrenceID] {
			t.Fatalf("finding %d occurrence ID = %q", index, finding.FindingOccurrenceID)
		}
		seen[finding.FindingOccurrenceID] = true
		if finding.RuleID == "" {
			t.Fatalf("finding %d has no canonical rule ID", index)
		}
	}
}

func TestEmitScanResultPreservesProvidedScanIDAndRejectsInvalid(t *testing.T) {
	const scanID = "57ab7d45-1ac3-4afd-9b9f-b7b684d73995"
	result := &ScanResult{ScanID: scanID, Scanner: "skill-scanner", Timestamp: time.Now().UTC()}
	got, err := EmitScanResult(t.Context(), nil, result, AgentIdentity{})
	if err != nil || got != scanID {
		t.Fatalf("provided scan ID = %q error=%v", got, err)
	}
	result.ScanID = "not-a-uuid"
	if _, err := EmitScanResult(t.Context(), nil, result, AgentIdentity{}); err == nil ||
		strings.Contains(err.Error(), result.ScanID) {
		t.Fatalf("invalid scan ID error = %v", err)
	}
}

func TestEnsureRuleIDSynthesis(t *testing.T) {
	finding := Finding{ID: "x", Severity: SeverityHigh, Title: "Hello World!", Scanner: "skill-scanner"}
	got := EnsureRuleID(&finding, "skill-scanner")
	if got == "" || !strings.Contains(got, "skill.") {
		t.Fatalf("rule ID = %q", got)
	}
}

func TestEmitScanResultConcurrentScanIDs(t *testing.T) {
	const count = 10
	var wait sync.WaitGroup
	ids := make([]string, count)
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			result := &ScanResult{Scanner: "mcp-scanner", Target: "target", Timestamp: time.Now().UTC()}
			id, err := EmitScanResult(context.Background(), nil, result, AgentIdentity{})
			if err != nil {
				t.Errorf("emit scan %d: %v", index, err)
				return
			}
			ids[index] = id
		}(index)
	}
	wait.Wait()
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || seen[id] {
			t.Fatalf("non-unique scan ID %q", id)
		}
		seen[id] = true
	}
}
