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

package watcher

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestCompareSnapshots_NoDrift(t *testing.T) {
	baseline := &audit.SnapshotRow{
		DependencyHashes: `{"requirements.txt":"abc123"}`,
		ConfigHashes:     `{"skill.yaml":"def456"}`,
		NetworkEndpoints: `["https://api.example.com"]`,
	}
	current := &TargetSnapshot{
		DependencyHashes: map[string]string{"requirements.txt": "abc123"},
		ConfigHashes:     map[string]string{"skill.yaml": "def456"},
		NetworkEndpoints: []string{"https://api.example.com"},
	}

	deltas := compareSnapshots(baseline, current)
	if len(deltas) != 0 {
		t.Errorf("expected no drift, got %d deltas: %v", len(deltas), deltas)
	}
}

func TestCompareSnapshots_DependencyChanged(t *testing.T) {
	baseline := &audit.SnapshotRow{
		DependencyHashes: `{"requirements.txt":"abc123"}`,
		ConfigHashes:     `{}`,
		NetworkEndpoints: `[]`,
	}
	current := &TargetSnapshot{
		DependencyHashes: map[string]string{"requirements.txt": "changed"},
		ConfigHashes:     map[string]string{},
		NetworkEndpoints: []string{},
	}

	deltas := compareSnapshots(baseline, current)
	if len(deltas) != 1 {
		t.Fatalf("expected 1 delta, got %d", len(deltas))
	}
	if deltas[0].Type != DriftDependencyChange {
		t.Errorf("expected dependency_change, got %s", deltas[0].Type)
	}
	if deltas[0].Severity != "MEDIUM" {
		t.Errorf("expected MEDIUM severity, got %s", deltas[0].Severity)
	}
}

func TestCompareSnapshots_NewDependency(t *testing.T) {
	baseline := &audit.SnapshotRow{
		DependencyHashes: `{}`,
		ConfigHashes:     `{}`,
		NetworkEndpoints: `[]`,
	}
	current := &TargetSnapshot{
		DependencyHashes: map[string]string{"package.json": "new-hash"},
		ConfigHashes:     map[string]string{},
		NetworkEndpoints: []string{},
	}

	deltas := compareSnapshots(baseline, current)
	if len(deltas) != 1 {
		t.Fatalf("expected 1 delta, got %d", len(deltas))
	}
	if deltas[0].Type != DriftDependencyChange {
		t.Errorf("expected dependency_change, got %s", deltas[0].Type)
	}
}

func TestCompareSnapshots_ConfigMutated(t *testing.T) {
	baseline := &audit.SnapshotRow{
		DependencyHashes: `{}`,
		ConfigHashes:     `{"skill.yaml":"old-hash"}`,
		NetworkEndpoints: `[]`,
	}
	current := &TargetSnapshot{
		DependencyHashes: map[string]string{},
		ConfigHashes:     map[string]string{"skill.yaml": "new-hash"},
		NetworkEndpoints: []string{},
	}

	deltas := compareSnapshots(baseline, current)
	if len(deltas) != 1 {
		t.Fatalf("expected 1 delta, got %d", len(deltas))
	}
	if deltas[0].Type != DriftConfigMutation {
		t.Errorf("expected config_mutation, got %s", deltas[0].Type)
	}
	if deltas[0].Severity != "HIGH" {
		t.Errorf("expected HIGH severity, got %s", deltas[0].Severity)
	}
}

func TestCompareSnapshots_NewEndpoint(t *testing.T) {
	baseline := &audit.SnapshotRow{
		DependencyHashes: `{}`,
		ConfigHashes:     `{}`,
		NetworkEndpoints: `["https://api.safe.com"]`,
	}
	current := &TargetSnapshot{
		DependencyHashes: map[string]string{},
		ConfigHashes:     map[string]string{},
		NetworkEndpoints: []string{"https://api.safe.com", "https://evil.com/exfil"},
	}

	deltas := compareSnapshots(baseline, current)
	if len(deltas) != 1 {
		t.Fatalf("expected 1 delta, got %d", len(deltas))
	}
	if deltas[0].Type != DriftNewEndpoint {
		t.Errorf("expected new_endpoint, got %s", deltas[0].Type)
	}
	if deltas[0].Severity != "HIGH" {
		t.Errorf("expected HIGH severity, got %s", deltas[0].Severity)
	}
}

func TestCompareSnapshots_RemovedEndpoint(t *testing.T) {
	baseline := &audit.SnapshotRow{
		DependencyHashes: `{}`,
		ConfigHashes:     `{}`,
		NetworkEndpoints: `["https://api.old.com","https://api.safe.com"]`,
	}
	current := &TargetSnapshot{
		DependencyHashes: map[string]string{},
		ConfigHashes:     map[string]string{},
		NetworkEndpoints: []string{"https://api.safe.com"},
	}

	deltas := compareSnapshots(baseline, current)
	if len(deltas) != 1 {
		t.Fatalf("expected 1 delta, got %d", len(deltas))
	}
	if deltas[0].Type != DriftRemovedEndpoint {
		t.Errorf("expected removed_endpoint, got %s", deltas[0].Type)
	}
	if deltas[0].Severity != "INFO" {
		t.Errorf("expected INFO severity, got %s", deltas[0].Severity)
	}
}

func TestCompareSnapshots_MultipleDrifts(t *testing.T) {
	baseline := &audit.SnapshotRow{
		DependencyHashes: `{"requirements.txt":"old"}`,
		ConfigHashes:     `{"config.yaml":"old"}`,
		NetworkEndpoints: `[]`,
	}
	current := &TargetSnapshot{
		DependencyHashes: map[string]string{"requirements.txt": "new"},
		ConfigHashes:     map[string]string{"config.yaml": "new"},
		NetworkEndpoints: []string{"https://new-endpoint.com"},
	}

	deltas := compareSnapshots(baseline, current)
	if len(deltas) != 3 {
		t.Errorf("expected 3 deltas, got %d: %+v", len(deltas), deltas)
	}
}

func TestDiffFindings_NewFinding(t *testing.T) {
	prev := []scanner.Finding{}
	curr := []scanner.Finding{
		{Title: "Hardcoded secret", Severity: "HIGH"},
	}

	deltas := diffFindings(prev, curr)
	if len(deltas) != 1 {
		t.Fatalf("expected 1 delta, got %d", len(deltas))
	}
	if deltas[0].Type != DriftNewFinding {
		t.Errorf("expected new_finding, got %s", deltas[0].Type)
	}
	if deltas[0].Severity != "HIGH" {
		t.Errorf("expected HIGH, got %s", deltas[0].Severity)
	}
}

func TestDiffFindings_ResolvedFinding(t *testing.T) {
	prev := []scanner.Finding{
		{Title: "Hardcoded secret", Severity: "HIGH"},
	}
	curr := []scanner.Finding{}

	deltas := diffFindings(prev, curr)
	if len(deltas) != 1 {
		t.Fatalf("expected 1 delta, got %d", len(deltas))
	}
	if deltas[0].Type != DriftRemovedFinding {
		t.Errorf("expected resolved_finding, got %s", deltas[0].Type)
	}
	if deltas[0].Severity != "INFO" {
		t.Errorf("expected INFO severity for resolved, got %s", deltas[0].Severity)
	}
}

func TestDiffFindings_NoChange(t *testing.T) {
	findings := []scanner.Finding{
		{Title: "Secret A", Severity: "MEDIUM"},
		{Title: "Secret B", Severity: "LOW"},
	}

	deltas := diffFindings(findings, findings)
	if len(deltas) != 0 {
		t.Errorf("expected no deltas, got %d", len(deltas))
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"CRITICAL", 5},
		{"HIGH", 4},
		{"MEDIUM", 3},
		{"LOW", 2},
		{"INFO", 1},
		{"UNKNOWN", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := severityRank(tt.input)
		if got != tt.expected {
			t.Errorf("severityRank(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestSummarizeDrift(t *testing.T) {
	deltas := []DriftDelta{
		{Type: DriftNewFinding, Severity: "HIGH"},
		{Type: DriftNewFinding, Severity: "MEDIUM"},
		{Type: DriftDependencyChange, Severity: "MEDIUM"},
		{Type: DriftConfigMutation, Severity: "HIGH"},
	}

	summary := summarizeDrift(deltas)
	if summary == "" {
		t.Error("expected non-empty summary")
	}
}

func TestDriftDelta_JSONRoundtrip(t *testing.T) {
	delta := DriftDelta{
		Type:        DriftNewEndpoint,
		Severity:    "HIGH",
		Description: "new network endpoint detected: https://evil.com",
		Current:     "https://evil.com",
	}

	data, err := json.Marshal(delta)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded DriftDelta
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Type != delta.Type {
		t.Errorf("type mismatch: %s != %s", decoded.Type, delta.Type)
	}
	if decoded.Severity != delta.Severity {
		t.Errorf("severity mismatch: %s != %s", decoded.Severity, delta.Severity)
	}
}
