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
	"os"
	"path/filepath"
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

func TestCompareSnapshots_RemovedDependency(t *testing.T) {
	baseline := &audit.SnapshotRow{
		DependencyHashes: `{"package.json":"old-hash"}`,
		ConfigHashes:     `{}`,
		NetworkEndpoints: `[]`,
		ContentHash:      "baseline-hash",
	}
	current := &TargetSnapshot{
		DependencyHashes: map[string]string{},
		ConfigHashes:     map[string]string{},
		NetworkEndpoints: []string{},
		ContentHash:      "current-hash",
	}

	deltas := compareSnapshots(baseline, current)
	if len(deltas) != 1 {
		t.Fatalf("expected 1 delta, got %d", len(deltas))
	}
	if deltas[0].Type != DriftDependencyChange {
		t.Errorf("expected dependency_change, got %s", deltas[0].Type)
	}
	if deltas[0].Description != "dependency manifest removed: package.json" {
		t.Errorf("unexpected description: %q", deltas[0].Description)
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

func TestCompareSnapshots_RemovedConfig(t *testing.T) {
	baseline := &audit.SnapshotRow{
		DependencyHashes: `{}`,
		ConfigHashes:     `{"skill.yaml":"old-hash"}`,
		NetworkEndpoints: `[]`,
		ContentHash:      "baseline-hash",
	}
	current := &TargetSnapshot{
		DependencyHashes: map[string]string{},
		ConfigHashes:     map[string]string{},
		NetworkEndpoints: []string{},
		ContentHash:      "current-hash",
	}

	deltas := compareSnapshots(baseline, current)
	if len(deltas) != 1 {
		t.Fatalf("expected 1 delta, got %d", len(deltas))
	}
	if deltas[0].Type != DriftConfigMutation {
		t.Errorf("expected config_mutation, got %s", deltas[0].Type)
	}
	if deltas[0].Description != "config file removed: skill.yaml" {
		t.Errorf("unexpected description: %q", deltas[0].Description)
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

func TestCompareSnapshots_ContentHashFallback(t *testing.T) {
	baseline := &audit.SnapshotRow{
		DependencyHashes: `{}`,
		ConfigHashes:     `{}`,
		NetworkEndpoints: `[]`,
		ContentHash:      "baseline-hash",
	}
	current := &TargetSnapshot{
		DependencyHashes: map[string]string{},
		ConfigHashes:     map[string]string{},
		NetworkEndpoints: []string{},
		ContentHash:      "current-hash",
	}

	deltas := compareSnapshots(baseline, current)
	if len(deltas) != 1 {
		t.Fatalf("expected 1 delta, got %d", len(deltas))
	}
	if deltas[0].Type != DriftContentChange {
		t.Errorf("expected content_change, got %s", deltas[0].Type)
	}
	if deltas[0].Severity != "MEDIUM" {
		t.Errorf("expected MEDIUM severity, got %s", deltas[0].Severity)
	}
}

func TestCompareSnapshots_MultipleDrifts(t *testing.T) {
	baseline := &audit.SnapshotRow{
		DependencyHashes: `{"requirements.txt":"old"}`,
		ConfigHashes:     `{"config.yaml":"old"}`,
		NetworkEndpoints: `[]`,
		ContentHash:      "baseline-hash",
	}
	current := &TargetSnapshot{
		DependencyHashes: map[string]string{"requirements.txt": "new"},
		ConfigHashes:     map[string]string{"config.yaml": "new"},
		NetworkEndpoints: []string{"https://new-endpoint.com"},
		ContentHash:      "current-hash",
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

func TestDiffFindings_SameTitleDifferentLocations(t *testing.T) {
	prev := []scanner.Finding{
		{Scanner: "skill-scanner", Title: "Hardcoded secret", Location: "a.py:1", Severity: "HIGH"},
	}
	curr := []scanner.Finding{
		{Scanner: "skill-scanner", Title: "Hardcoded secret", Location: "a.py:1", Severity: "HIGH"},
		{Scanner: "skill-scanner", Title: "Hardcoded secret", Location: "b.py:5", Severity: "HIGH"},
	}

	deltas := diffFindings(prev, curr)
	if len(deltas) != 1 {
		t.Fatalf("expected 1 delta, got %d", len(deltas))
	}
	if deltas[0].Type != DriftNewFinding {
		t.Errorf("expected new_finding, got %s", deltas[0].Type)
	}
	if deltas[0].Current != "Hardcoded secret (b.py:5)" {
		t.Errorf("unexpected current label: %q", deltas[0].Current)
	}
}

func TestDiffFindings_SeverityChange(t *testing.T) {
	prev := []scanner.Finding{
		{Scanner: "skill-scanner", Title: "Hardcoded secret", Location: "main.py:7", Severity: "MEDIUM"},
	}
	curr := []scanner.Finding{
		{Scanner: "skill-scanner", Title: "Hardcoded secret", Location: "main.py:7", Severity: "CRITICAL"},
	}

	deltas := diffFindings(prev, curr)
	if len(deltas) != 1 {
		t.Fatalf("expected 1 delta, got %d", len(deltas))
	}
	if deltas[0].Type != DriftSeverityChange {
		t.Errorf("expected severity_escalation, got %s", deltas[0].Type)
	}
	if deltas[0].Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", deltas[0].Severity)
	}
	if deltas[0].Previous != "MEDIUM" || deltas[0].Current != "CRITICAL" {
		t.Errorf("unexpected severity transition: %q -> %q", deltas[0].Previous, deltas[0].Current)
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
		{Scanner: "skill-scanner", Title: "Secret A", Location: "a.py:1", Severity: "MEDIUM"},
		{Scanner: "skill-scanner", Title: "Secret B", Location: "b.py:2", Severity: "LOW"},
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
		got := audit.SeverityRank(tt.input)
		if got != tt.expected {
			t.Errorf("audit.SeverityRank(%q) = %d, want %d", tt.input, got, tt.expected)
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

func TestEnumerateTargets_IncludesConfiguredMCPServers(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	t.Setenv("PATH", "")

	pluginDir := filepath.Join(cfg.DataDir, "plugins")
	if err := os.MkdirAll(filepath.Join(skillDir, "watched-skill"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(pluginDir, "watched-plugin"), 0o700); err != nil {
		t.Fatal(err)
	}

	ocPath := filepath.Join(cfg.DataDir, "openclaw.json")
	ocData := `{
		"mcp": {
			"servers": {
				"remote-mcp": {"url": "https://example.com/mcp"},
				"stdio-mcp": {"command": "npx", "args": ["-y", "mcp-server"]}
			}
		}
	}`
	if err := os.WriteFile(ocPath, []byte(ocData), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Claw.ConfigFile = ocPath

	w := New(cfg, []string{skillDir}, []string{pluginDir}, store, logger, nil, nil, nil, nil)
	targets := w.enumerateTargets()

	seen := make(map[InstallType]map[string]InstallEvent)
	for _, target := range targets {
		if seen[target.Type] == nil {
			seen[target.Type] = make(map[string]InstallEvent)
		}
		seen[target.Type][target.Name] = target
	}

	if _, ok := seen[InstallSkill]["watched-skill"]; !ok {
		t.Fatalf("expected watched skill in targets, got %+v", targets)
	}
	if _, ok := seen[InstallPlugin]["watched-plugin"]; !ok {
		t.Fatalf("expected watched plugin in targets, got %+v", targets)
	}
	if evt, ok := seen[InstallMCP]["remote-mcp"]; !ok {
		t.Fatalf("expected remote MCP in targets, got %+v", targets)
	} else if evt.Path != "remote-mcp" {
		t.Fatalf("remote MCP path = %q, want server name", evt.Path)
	}
	if evt, ok := seen[InstallMCP]["stdio-mcp"]; !ok {
		t.Fatalf("expected stdio MCP in targets, got %+v", targets)
	} else if evt.Path != "stdio-mcp" {
		t.Fatalf("stdio MCP path = %q, want server name", evt.Path)
	}
}

func TestSnapshotMCPServer_UsesConfigEntryAndEndpoint(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	t.Setenv("PATH", "")

	ocPath := filepath.Join(cfg.DataDir, "openclaw.json")
	ocData := `{
		"mcp": {
			"servers": {
				"remote-mcp": {"url": "https://example.com/mcp", "transport": "http"}
			}
		}
	}`
	if err := os.WriteFile(ocPath, []byte(ocData), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Claw.ConfigFile = ocPath

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil, nil, nil)
	snap, err := w.snapshotMCPServer("remote-mcp")
	if err != nil {
		t.Fatalf("snapshotMCPServer: %v", err)
	}

	key := "mcp.servers.remote-mcp"
	if snap.ConfigHashes[key] == "" {
		t.Fatalf("expected config hash for %q, got %+v", key, snap.ConfigHashes)
	}
	if len(snap.NetworkEndpoints) != 1 || snap.NetworkEndpoints[0] != "https://example.com/mcp" {
		t.Fatalf("unexpected endpoints: %+v", snap.NetworkEndpoints)
	}
	if snap.ContentHash == "" {
		t.Fatal("expected non-empty content hash")
	}
}
