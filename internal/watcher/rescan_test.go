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
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
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

func TestEnumerateTargetsSkipsBundledSkillRoot(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	t.Setenv("CODEX_HOME", filepath.Dir(skillDir))
	cfg.Guardrail.Connector = "codex"
	systemRoot := filepath.Join(skillDir, ".system")
	if err := os.MkdirAll(filepath.Join(systemRoot, "imagegen"), 0o700); err != nil {
		t.Fatal(err)
	}
	w := &InstallWatcher{
		cfg: cfg, skillDirs: []string{systemRoot}, store: store, logger: logger,
	}

	for _, target := range w.enumerateTargets() {
		if target.Type == InstallSkill {
			t.Fatalf("bundled skill entered periodic rescan targets: %+v", target)
		}
	}
}

func TestEnumerateTargetsExpandsHermesSkillsAndSkipsOnlyProvenBundles(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	home := t.TempDir()
	t.Setenv("HERMES_HOME", home)
	cfg.Guardrail.Connector = "hermes"
	root := filepath.Join(home, "skills")
	bundled := filepath.Join(root, "productivity", "vendor-docs")
	source := filepath.Join(home, "hermes-agent", "skills", "productivity", "vendor-docs")
	forged := filepath.Join(root, "productivity", "manifest-only")
	user := filepath.Join(root, "operator-skill")
	bundledMarker := []byte("---\nname: vendor-docs\n---\n")
	for path, marker := range map[string][]byte{
		bundled: bundledMarker,
		source:  bundledMarker,
		forged:  []byte("---\nname: manifest-only\n---\n"),
		user:    []byte("---\nname: operator-skill\n---\n"),
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "SKILL.md"), marker, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bundledHash := md5.Sum(append([]byte("SKILL.md"), bundledMarker...)) // #nosec G401 -- Hermes fixture.
	forgedMarker, err := os.ReadFile(filepath.Join(forged, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	forgedHash := md5.Sum(append([]byte("SKILL.md"), forgedMarker...)) // #nosec G401 -- Hermes fixture.
	manifest := fmt.Sprintf("vendor-docs:%x\nmanifest-only:%x\n", bundledHash, forgedHash)
	if err := os.WriteFile(filepath.Join(root, ".bundled_manifest"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{root}, nil, store, logger, nil, nil)
	targets := w.enumerateTargets()
	got := make(map[string]InstallEvent)
	for _, target := range targets {
		if target.Type == InstallSkill {
			got[target.Name] = target
		}
	}
	if _, ok := got["vendor-docs"]; ok {
		t.Fatalf("proven Hermes bundle entered periodic rescan: %+v", targets)
	}
	if _, ok := got["productivity"]; ok {
		t.Fatalf("Hermes category entered periodic rescan: %+v", targets)
	}
	for name, path := range map[string]string{"manifest-only": forged, "operator-skill": user} {
		target, ok := got[name]
		if !ok || !sameWatcherPath(target.Path, path) || target.Connector != "hermes" {
			t.Fatalf("Hermes scan target %q = %+v", name, target)
		}
	}

	events := w.pendingInstallEvents(filepath.Join(root, "productivity"))
	byName := make(map[string]InstallEvent, len(events))
	for _, event := range events {
		byName[event.Name] = event
	}
	if _, ok := byName["productivity"]; ok {
		t.Fatalf("category notification was not expanded: %+v", events)
	}
	if _, ok := byName["vendor-docs"]; !ok {
		t.Fatalf("bundled identity missing from live expansion: %+v", events)
	}
	if _, ok := byName["manifest-only"]; !ok {
		t.Fatalf("scanable forged identity missing from live expansion: %+v", events)
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

	w := New(cfg, []string{skillDir}, []string{pluginDir}, store, logger, nil, nil)
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

// TestRescan_FromZeptoClawConfig — plan E1 / item 5. Mirrors the
// existing TestEnumerateTargets_IncludesConfiguredMCPServers shape but
// drives ReadMCPServers through the connector dispatcher: with
// guardrail.connector="zeptoclaw" the watcher's enumerator MUST pick
// up MCP servers declared in $HOME/.zeptoclaw/config.json — not from
// openclaw.json.
//
// We isolate $HOME via t.Setenv so the connector-specific reader
// (which uses os.UserHomeDir directly, no override) lands in our tmpdir
// and not on the developer's real home.
func TestRescan_FromZeptoClawConfig(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	t.Setenv("PATH", "")
	tmpHome := t.TempDir()
	testenv.SetHome(t, tmpHome)

	zcDir := filepath.Join(tmpHome, ".zeptoclaw")
	if err := os.MkdirAll(zcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	zcConfig := `{
		"providers": {"openai": {"api_base": "https://api.openai.com"}},
		"mcp": {
			"servers": {
				"zc-remote": {"url": "https://example.com/mcp", "transport": "http"},
				"zc-stdio":  {"command": "npx", "args": ["-y", "mcp-zc"]}
			}
		}
	}`
	if err := os.WriteFile(filepath.Join(zcDir, "config.json"), []byte(zcConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Guardrail.Connector = "zeptoclaw"

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	targets := w.enumerateTargets()

	mcpByName := make(map[string]InstallEvent)
	for _, t := range targets {
		if t.Type == InstallMCP {
			mcpByName[t.Name] = t
		}
	}
	for _, name := range []string{"zc-remote", "zc-stdio"} {
		if _, ok := mcpByName[name]; !ok {
			t.Errorf("expected zeptoclaw MCP %q in targets, got %+v", name, mcpByName)
		}
	}
}

// TestRescan_FromClaudeMCPScopes drives enumerateTargets through Claude's
// canonical local/project/user MCP state and pins local > project > user.
func TestRescan_FromClaudeMCPScopes(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	t.Setenv("PATH", "")
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	tmpHome := t.TempDir()
	testenv.SetHome(t, tmpHome)
	workspace := filepath.Join(tmpHome, "workspace")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	ccState := fmt.Sprintf(`{
		"projects": {
			%q: {
				"mcpServers": {
					"cc-shared": {"command": "local-command"},
					"cc-local": {"command": "local-command"}
				}
			}
		},
		"mcpServers": {
			"cc-shared": {"command": "user-command"},
			"cc-user": {"command": "user-command"}
		}
	}`, workspace)
	if err := os.WriteFile(filepath.Join(tmpHome, ".claude.json"), []byte(ccState), 0o600); err != nil {
		t.Fatal(err)
	}
	projectMCP := `{"mcpServers":{
		"cc-shared":{"command":"project-command"},
		"cc-project":{"command":"project-command"}
	}}`
	if err := os.WriteFile(filepath.Join(workspace, ".mcp.json"), []byte(projectMCP), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Guardrail.Connector = "claudecode"
	cfg.Claw.WorkspaceDir = workspace

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	targets := w.enumerateTargets()

	mcpByName := make(map[string]InstallEvent)
	for _, t := range targets {
		if t.Type == InstallMCP {
			mcpByName[t.Name] = t
		}
	}
	for _, name := range []string{"cc-shared", "cc-local", "cc-project", "cc-user"} {
		if _, ok := mcpByName[name]; !ok {
			t.Errorf("expected claudecode MCP %q in targets, got %+v", name, mcpByName)
		}
	}
	servers, err := cfg.ReadMCPServers()
	if err != nil {
		t.Fatal(err)
	}
	var sharedCommand string
	for _, server := range servers {
		if server.Name == "cc-shared" {
			sharedCommand = server.Command
			break
		}
	}
	if got := sharedCommand; got != "local-command" {
		t.Errorf("cc-shared command = %q, want local-command", got)
	}
}

func TestEnumerateClaudeWatcherPluginsUsesManifestlessCacheVersionBoundary(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "plugins", "cache")
	version := filepath.Join(cache, "official", "manifestless", "sha-123")
	nestedManifest := filepath.Join(version, "node_modules", "nested", ".claude-plugin")
	if err := os.MkdirAll(nestedManifest, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(nestedManifest, "plugin.json"),
		[]byte(`{"name":"must-not-be-a-plugin-root"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	got := enumerateClaudeWatcherPlugins(cache)
	if len(got) != 1 || !sameWatcherPath(got[0], version) {
		t.Fatalf("cache plugin roots = %v, want only %q", got, version)
	}
	if identity := claudeWatcherPluginIdentity(cache, version); identity != "manifestless@official" {
		t.Fatalf("cache plugin identity = %q", identity)
	}
}

// TestRescan_FromCodexConfigToml — Codex discovers MCP entries from the user
// ~/.codex/config.toml table; pinned workspaces additionally contribute layered
// .codex/config.toml entries, subject to the client's project trust decision.
func TestRescan_FromCodexConfigToml(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	t.Setenv("PATH", "")

	home := t.TempDir()
	testenv.SetHome(t, home)
	codexDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configTOML := `[mcp_servers.codex-stdio]
command = "node"
args = ["mcp.js"]
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(configTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Guardrail.Connector = "codex"

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	targets := w.enumerateTargets()

	var saw bool
	for _, t := range targets {
		if t.Type == InstallMCP && t.Name == "codex-stdio" {
			saw = true
			break
		}
	}
	if !saw {
		t.Errorf("expected codex-stdio MCP in targets, got %+v", targets)
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

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
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

func TestEnumerateTargetsSkipsOwnBundledPlugin(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	pluginDir := filepath.Join(filepath.Dir(skillDir), "plugins")
	own := filepath.Join(pluginDir, "defenseclaw")
	other := filepath.Join(pluginDir, "other")
	for _, d := range []string{own, other} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	w := New(cfg, nil, []string{pluginDir}, store, logger, nil, nil)
	w.SetBundledPluginCheck(func(path string) bool { return path == own })

	var plugins []string
	for _, target := range w.enumerateTargets() {
		if target.Type == InstallPlugin {
			plugins = append(plugins, target.Path)
		}
	}
	if len(plugins) != 1 || plugins[0] != other {
		t.Fatalf("rescan plugin targets = %v, want only %s", plugins, other)
	}
}

// GAP-2338: Hermes' plugins folder is a Python package with a __pycache__
// dir. Neither the rescan nor a live create event treats it (or
// node_modules) as a plugin.
func TestPluginRootSkipsBytecodeAndDependencyDirs(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	pluginDir := filepath.Join(filepath.Dir(skillDir), "plugins")
	plugin := filepath.Join(pluginDir, "disk-cleanup")
	for _, d := range []string{plugin, filepath.Join(pluginDir, "__pycache__"), filepath.Join(pluginDir, "node_modules")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	w := New(cfg, nil, []string{pluginDir}, store, logger, nil, nil)

	var plugins []string
	for _, target := range w.enumerateTargets() {
		if target.Type == InstallPlugin {
			plugins = append(plugins, target.Path)
		}
	}
	if len(plugins) != 1 || plugins[0] != plugin {
		t.Fatalf("rescan plugin targets = %v, want only %s", plugins, plugin)
	}
	if w.isDirectChildDir(filepath.Join(pluginDir, "__pycache__")) || !w.isDirectChildDir(plugin) {
		t.Fatal("live create events must admit plugins but not __pycache__")
	}
}

// GAP-1525: on an upgrade the old copy of DefenseClaw's own OpenClaw plugin
// is still on disk when the startup rescan runs; connector setup replaces it
// moments later. The startup cycle must not scan that dir, while a later
// cycle still scans it if it really differs from the bundled copy.
func TestStartupRescanDefersStaleOwnPluginDir(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	pluginDir := filepath.Join(filepath.Dir(skillDir), "plugins")
	own := filepath.Join(pluginDir, "defenseclaw")
	if err := os.MkdirAll(own, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(own, "index.js"), []byte("// older release\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, nil, []string{pluginDir}, store, logger, nil, nil)
	w.SetBundledPluginCheck(func(string) bool { return false })
	w.SetBundledPluginDir(own)
	var scanned []string
	w.scannerFactory = func(evt InstallEvent) scanner.Scanner {
		scanned = append(scanned, evt.Path)
		return nil
	}

	w.runRescanCycle(context.Background())
	if len(scanned) != 0 {
		t.Fatalf("startup rescan scanned %v, want the own plugin dir deferred", scanned)
	}
	w.runRescanCycle(context.Background())
	if len(scanned) != 1 || scanned[0] != own {
		t.Fatalf("second rescan scanned %v, want %s (still differs from the bundle)", scanned, own)
	}
}

// GAP-2384: a deferred watch folder (Hermes before its first run) and a
// missing agent config are skipped quietly, as the watcher does.
func TestEnumerateTargetsSkipsMissingDeferredDirsQuietly(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	home := t.TempDir()
	t.Setenv("HERMES_HOME", home)
	cfg.Guardrail.Connector = "hermes"
	missing := filepath.Join(home, "hermes-agent", "plugins")

	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = wr
	w := New(cfg, []string{filepath.Join(home, "skills")}, []string{missing}, store, logger, nil, nil)
	targets := w.enumerateTargets()
	os.Stderr = orig
	_ = wr.Close()
	out, _ := io.ReadAll(r)

	if len(targets) != 0 {
		t.Fatalf("targets = %+v, want none", targets)
	}
	if strings.Contains(string(out), "[rescan]") {
		t.Fatalf("rescan logged an error for a deferred folder: %s", out)
	}
}
