// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// fakeScanPersistence captures what scan_persist would have written
// so tests can assert on enrichment without a live SQLite store.
type fakeScanPersistence struct {
	summary  ScanSummaryParams
	findings []Finding
}

func (f *fakeScanPersistence) InsertScanSummary(p ScanSummaryParams) error {
	f.summary = p
	return nil
}
func (f *fakeScanPersistence) InsertScanFindings(scanID, target string, findings []Finding, meta ScanFindingMeta) error {
	f.findings = append(f.findings, findings...)
	return nil
}

func TestFindingEnricher_PopulatesDataAxis(t *testing.T) {
	// Install a fake enricher that labels anything starting "SEC-" as
	// sensitive_access. The real hook is installed by the cli wiring
	// layer; this test verifies the mechanism itself.
	original := findingEnricher
	defer func() { findingEnricher = original }()
	SetFindingEnricher(func(f *Finding) []string {
		if f.RuleID == "SEC-AWS-KEY" {
			return []string{"sensitive_access"}
		}
		return nil
	})

	pers := &fakeScanPersistence{}
	result := &ScanResult{
		Scanner:   "test",
		Target:    "t",
		Timestamp: time.Now(),
		Findings: []Finding{
			{ID: "1", Severity: SeverityCritical, Title: "aws key", RuleID: "SEC-AWS-KEY"},
			{ID: "2", Severity: SeverityLow, Title: "noise", RuleID: "UNKNOWN-RULE"},
		},
	}

	_, err := EmitScanResult(context.Background(), pers, result, AgentIdentity{})
	if err != nil {
		t.Fatalf("EmitScanResult: %v", err)
	}
	if len(pers.findings) != 2 {
		t.Fatalf("captured %d findings, want 2", len(pers.findings))
	}
	if !reflect.DeepEqual(pers.findings[0].DataAxis, []string{"sensitive_access"}) {
		t.Errorf("SEC-AWS-KEY DataAxis = %v, want [sensitive_access]", pers.findings[0].DataAxis)
	}
	if len(pers.findings[1].DataAxis) != 0 {
		t.Errorf("UNKNOWN-RULE DataAxis = %v, want empty", pers.findings[1].DataAxis)
	}
}

func TestFindingEnricher_DoesNotOverwriteExistingAxes(t *testing.T) {
	original := findingEnricher
	defer func() { findingEnricher = original }()
	SetFindingEnricher(func(f *Finding) []string {
		return []string{"should_not_be_used"}
	})

	pers := &fakeScanPersistence{}
	result := &ScanResult{
		Scanner:   "test",
		Target:    "t",
		Timestamp: time.Now(),
		Findings: []Finding{
			{
				ID: "1", Severity: SeverityHigh, Title: "prelabeled",
				RuleID: "SOME-RULE", DataAxis: []string{"egress_external"},
			},
		},
	}

	_, err := EmitScanResult(context.Background(), pers, result, AgentIdentity{})
	if err != nil {
		t.Fatalf("EmitScanResult: %v", err)
	}
	if !reflect.DeepEqual(pers.findings[0].DataAxis, []string{"egress_external"}) {
		t.Errorf("prelabeled DataAxis overwritten; got %v", pers.findings[0].DataAxis)
	}
}
