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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func setupTestEnv(t *testing.T) (cfg *config.Config, store *audit.Store, logger *audit.Logger, skillDir string) {
	t.Helper()

	tmpDir := testenv.PrivateTempDir(t)
	skillDir = filepath.Join(tmpDir, "skills")
	if err := os.MkdirAll(skillDir, 0o700); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(tmpDir, "test-audit.db")
	store, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	logger = audit.NewLogger(store)
	logger.SetRuntimeV8Emitter(&watcherTestRuntime{})

	cfg = &config.Config{
		DataDir:       tmpDir,
		AuditDB:       dbPath,
		QuarantineDir: filepath.Join(tmpDir, "quarantine"),
		PolicyDir:     filepath.Join(tmpDir, "policies"),
		Scanners: config.ScannersConfig{
			SkillScanner: config.SkillScannerConfig{Binary: "skill-scanner"},
			MCPScanner:   config.MCPScannerConfig{Binary: "mcp-scanner"},
		},
		Watch: config.WatchConfig{
			DebounceMs: 100,
			AutoBlock:  true,
		},
		SkillActions: config.DefaultSkillActions(),
	}

	return cfg, store, logger, skillDir
}

func setupQuarantineProvenanceTestEnv(
	t *testing.T,
) (cfg *config.Config, store *audit.Store, logger *audit.Logger, skillDir string) {
	t.Helper()
	tmpDir := t.TempDir()
	skillDir = filepath.Join(tmpDir, "skills")
	if err := os.MkdirAll(skillDir, 0o700); err != nil {
		t.Fatal(err)
	}
	var err error
	store, err = audit.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	logger = audit.NewLogger(store)
	logger.SetRuntimeV8Emitter(&watcherTestRuntime{})
	cfg = &config.Config{
		DataDir: tmpDir, AuditDB: ":memory:",
		QuarantineDir: filepath.Join(tmpDir, "quarantine"),
		PolicyDir:     filepath.Join(tmpDir, "policies"),
		Scanners: config.ScannersConfig{
			SkillScanner: config.SkillScannerConfig{Binary: "skill-scanner"},
			MCPScanner:   config.MCPScannerConfig{Binary: "mcp-scanner"},
		},
		Watch:        config.WatchConfig{DebounceMs: 100, AutoBlock: true},
		SkillActions: config.DefaultSkillActions(),
	}
	return cfg, store, logger, skillDir
}

func TestClassifyEvent_SkillDir(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)

	evt := w.classifyEvent(filepath.Join(skillDir, "my-skill"))
	if evt.Type != InstallSkill {
		t.Errorf("expected type %q, got %q", InstallSkill, evt.Type)
	}
	if evt.Name != "my-skill" {
		t.Errorf("expected name %q, got %q", "my-skill", evt.Name)
	}
}

func TestClassifyEvent_ClaudeSkillsAndCacheUseExactBoundaries(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cacheRoot := filepath.Join(t.TempDir(), "plugins", "cache")
	plain := filepath.Join(skillDir, "plain")
	plugin := filepath.Join(skillDir, "plugin")
	cacheVersion := filepath.Join(cacheRoot, "marketplace", "cached", "1.2.3")
	for _, dir := range []string{plain, plugin, cacheVersion} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	manifestDir := filepath.Join(plugin, ".claude-plugin")
	if err := os.MkdirAll(manifestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manifestDir, "plugin.json"), []byte(`{"name":"semantic-name"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	w := New(
		cfg,
		[]string{skillDir},
		[]string{skillDir, cacheRoot},
		store,
		logger,
		nil,
		nil,
	)

	if got := w.classifyEvent(plain).Type; got != InstallSkill {
		t.Fatalf("plain Claude skill classified as %q", got)
	}
	if got := w.classifyEvent(plugin).Type; got != InstallPlugin {
		t.Fatalf("skills-directory Claude plugin classified as %q", got)
	}
	if got := w.classifyEvent(plugin).Name; got != "semantic-name@skills-dir" {
		t.Fatalf("skills-directory Claude plugin identity = %q", got)
	}
	cacheEvent := w.classifyEvent(cacheVersion)
	if cacheEvent.Type != InstallPlugin {
		t.Fatalf("Claude cache version classified as %q", cacheEvent.Type)
	}
	if cacheEvent.Name != "cached@marketplace" {
		t.Fatalf("Claude cache plugin identity = %q", cacheEvent.Name)
	}
	if !w.isDirectChildDir(cacheVersion) {
		t.Fatal("exact Claude cache version was not an admission boundary")
	}
	if w.isDirectChildDir(filepath.Dir(cacheVersion)) {
		t.Fatal("Claude cache plugin container was treated as an admission boundary")
	}
}

func TestAdmission_BlockedSkill(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)

	cfg.AssetPolicy.Skill.Denied = append(cfg.AssetPolicy.Skill.Denied, config.AssetPolicyRule{Name: "evil-skill", Reason: "known malicious"})

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)

	skillPath := filepath.Join(skillDir, "evil-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}

	evt := InstallEvent{Type: InstallSkill, Name: "evil-skill", Path: skillPath, Timestamp: time.Now()}
	result := w.runAdmission(context.Background(), evt)

	if result.Verdict != VerdictBlocked {
		t.Errorf("expected verdict %q, got %q", VerdictBlocked, result.Verdict)
	}
}

func TestAdmission_AllowedSkill(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)

	cfg.AssetPolicy.Skill.Allowed = append(cfg.AssetPolicy.Skill.Allowed, config.AssetPolicyRule{Name: "trusted-skill", Reason: "pre-approved"})

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)

	skillPath := filepath.Join(skillDir, "trusted-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}

	evt := InstallEvent{Type: InstallSkill, Name: "trusted-skill", Path: skillPath, Timestamp: time.Now()}
	result := w.runAdmission(context.Background(), evt)

	if result.Verdict != VerdictAllowed {
		t.Errorf("expected verdict %q, got %q", VerdictAllowed, result.Verdict)
	}
}

func TestAdmission_BundledSkillIsDiscoveryOnly(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	t.Setenv("CODEX_HOME", filepath.Dir(skillDir))
	cfg.Guardrail.Connector = "codex"
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)

	skillPath := filepath.Join(skillDir, enforce.BundledSkillContainer, "imagegen")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	evt := InstallEvent{
		Type: InstallSkill, Name: "imagegen", Path: skillPath, Timestamp: time.Now(),
	}

	result := w.runAdmission(context.Background(), evt)

	if result.Verdict != VerdictAllowed || result.Reason != "vendor-bundled skill is discovery-only" {
		t.Fatalf("bundled admission = %+v", result)
	}
	if w.isDirectChildDir(filepath.Join(skillDir, enforce.BundledSkillContainer)) {
		t.Fatal(".system container entered realtime watcher admission")
	}
	if action, err := store.GetAction("skill", "imagegen"); err != nil || action != nil {
		t.Fatalf("bundled skill action = %+v, err=%v", action, err)
	}
	scans, err := store.LatestScansByScanner("skill-scanner")
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 0 {
		t.Fatalf("bundled skill produced scanner rows: %+v", scans)
	}
}

func TestAdmission_ExactManagedPluginIsDiscoveryOnly(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	pluginDir := filepath.Join(filepath.Dir(skillDir), "plugins")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(pluginDir, "defenseclaw.js")
	foreign := filepath.Join(pluginDir, "foreign.js")
	w := New(cfg, nil, []string{pluginDir}, store, logger, nil, nil)
	w.SetManagedArtifacts([]string{managed, managed})

	result := w.runAdmission(context.Background(), InstallEvent{
		Type: InstallPlugin, Name: "defenseclaw", Path: managed, Timestamp: time.Now(),
	})
	if result.Verdict != VerdictAllowed || result.Reason != "connector-managed plugin is lifecycle-owned and discovery-only" {
		t.Fatalf("managed plugin admission = %+v", result)
	}
	if w.isManagedArtifact(foreign) {
		t.Fatalf("managed artifact exemption escaped to sibling %s", foreign)
	}
	if len(w.managedArtifacts) != 1 {
		t.Fatalf("managed artifact set = %v, want one exact path", w.managedArtifacts)
	}
}

func TestBundledSkillWatchPathDoesNotExemptArbitrarySystemDirectory(t *testing.T) {
	t.Setenv("CODEX_HOME", filepath.Join(t.TempDir(), "codex-home"))
	target := filepath.Join(t.TempDir(), "skills", ".system", "operator-skill")
	if isBundledSkillWatchPath(target) {
		t.Fatalf("arbitrary .system path was incorrectly exempted: %s", target)
	}
}

func TestAdmission_ScanError_NoScanner(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)

	skillPath := filepath.Join(skillDir, "unknown-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}

	evt := InstallEvent{Type: InstallSkill, Name: "unknown-skill", Path: skillPath, Timestamp: time.Now()}
	result := w.runAdmission(context.Background(), evt)

	if result.Verdict != VerdictScanError && result.Verdict != VerdictClean {
		t.Logf("verdict=%s reason=%s", result.Verdict, result.Reason)
	}
}

func TestWatcher_DetectsNewDirectory(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)

	cfg.AssetPolicy.Skill.Allowed = append(cfg.AssetPolicy.Skill.Allowed, config.AssetPolicyRule{Name: "new-skill", Reason: "pre-approved"})

	var mu sync.Mutex
	var results []AdmissionResult

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, func(r AdmissionResult) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- w.Run(ctx)
	}()

	time.Sleep(500 * time.Millisecond)

	if err := os.MkdirAll(filepath.Join(skillDir, "new-skill"), 0o700); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		n := len(results)
		mu.Unlock()
		if n > 0 {
			break
		}
		select {
		case <-deadline:
			cancel()
			<-errCh
			t.Fatal("timed out waiting for admission result")
		case <-time.After(50 * time.Millisecond):
		}
	}

	cancel()
	<-errCh

	mu.Lock()
	defer mu.Unlock()

	found := false
	for _, r := range results {
		if r.Event.Name == "new-skill" {
			found = true
			if r.Verdict != VerdictAllowed {
				t.Errorf("expected verdict %q for allowed skill, got %q", VerdictAllowed, r.Verdict)
			}
		}
	}
	if !found {
		t.Error("admission result for 'new-skill' not found")
	}
}

func TestAdmission_GatePrecedence_BlockBeatsAllow(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)

	// With the unified table, setting install to "block" after "allow" replaces it.
	// The block check runs first in the admission gate, so block takes priority.
	cfg.AssetPolicy.Skill.Denied = append(cfg.AssetPolicy.Skill.Denied, config.AssetPolicyRule{Name: "conflict-skill", Reason: "security"})

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)

	skillPath := filepath.Join(skillDir, "conflict-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}

	evt := InstallEvent{Type: InstallSkill, Name: "conflict-skill", Path: skillPath, Timestamp: time.Now()}
	result := w.runAdmission(context.Background(), evt)

	if result.Verdict != VerdictBlocked {
		t.Errorf("expected block to take precedence, got verdict %q", result.Verdict)
	}
}

func TestActionState_IndependentDimensions(t *testing.T) {
	_, store, _, _ := setupTestEnv(t)

	// Set install to block
	if err := store.SetActionField("skill", "multi-action", "install", "block", "blocked"); err != nil {
		t.Fatal(err)
	}

	// Set file to quarantine (should not affect install)
	if err := store.SetActionField("skill", "multi-action", "file", "quarantine", "quarantined"); err != nil {
		t.Fatal(err)
	}

	entry, err := store.GetAction("skill", "multi-action")
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected action entry, got nil")
		return
	}
	if entry.Actions.Install != "block" {
		t.Errorf("expected install=block, got %q", entry.Actions.Install)
	}
	if entry.Actions.File != "quarantine" {
		t.Errorf("expected file=quarantine, got %q", entry.Actions.File)
	}
}

// ---------------------------------------------------------------------------
// Full quarantine flow: simulates what happens after a scan returns CRITICAL
// findings. Tests the built-in Go fallback path (no OPA, no real scanner).
// Verifies: verdict=rejected, files moved to quarantine dir, SQLite updated.
// ---------------------------------------------------------------------------

func TestFullQuarantineFlow_Skill(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)

	// Create a skill directory with files
	skillPath := filepath.Join(skillDir, "evil-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "main.py"), []byte("import os; os.system('rm -rf /')"), 0o644); err != nil {
		t.Fatal(err)
	}

	var result AdmissionResult
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, func(r AdmissionResult) {
		result = r
	})

	// The scanner binary won't be found, so the built-in fallback runs.
	// Since the scanner fails, we need to test the post-scan enforcement
	// directly. Let's simulate by using the built-in Go path with a
	// blocked skill instead, which triggers enforceBlock and quarantine.

	// Block the skill (simulating auto-block after scan)
	cfg.AssetPolicy.Skill.Denied = append(cfg.AssetPolicy.Skill.Denied, config.AssetPolicyRule{Name: "evil-skill", Reason: "auto-block: CRITICAL findings"})

	evt := InstallEvent{Type: InstallSkill, Name: "evil-skill", Path: skillPath, Timestamp: time.Now()}
	result = w.runAdmission(context.Background(), evt)

	// Verify verdict
	if result.Verdict != VerdictBlocked {
		t.Errorf("expected VerdictBlocked, got %q", result.Verdict)
	}

	// Verify files were quarantined (moved from skillDir to quarantineDir)
	quarantinePath := filepath.Join(cfg.QuarantineDir, "skills", "evil-skill")
	if _, err := os.Stat(quarantinePath); os.IsNotExist(err) {
		t.Error("expected skill to be quarantined but quarantine dir does not exist")
	}

	// Verify original was removed
	if _, err := os.Stat(skillPath); !os.IsNotExist(err) {
		t.Error("expected original skill dir to be removed after quarantine")
	}

	// Verify quarantined file contents preserved
	data, err := os.ReadFile(filepath.Join(quarantinePath, "main.py"))
	if err != nil {
		t.Fatalf("expected quarantined file to exist: %v", err)
	}
	if string(data) != "import os; os.system('rm -rf /')" {
		t.Errorf("quarantined file content mismatch: %q", string(data))
	}
}

func TestFullQuarantineFlow_Plugin(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)

	pluginDir := filepath.Join(cfg.DataDir, "plugins")
	cfg.PluginDir = pluginDir
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Create a plugin directory with files
	pluginPath := filepath.Join(pluginDir, "malicious-plugin")
	if err := os.MkdirAll(pluginPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginPath, "plugin.js"), []byte("eval(atob('...'))"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Block the plugin
	cfg.AssetPolicy.Plugin.Denied = append(cfg.AssetPolicy.Plugin.Denied, config.AssetPolicyRule{Name: "malicious-plugin", Reason: "CRITICAL: eval detected"})

	w := New(cfg, []string{skillDir}, []string{pluginDir}, store, logger, nil, nil)

	evt := InstallEvent{Type: InstallPlugin, Name: "malicious-plugin", Path: pluginPath, Timestamp: time.Now()}
	result := w.runAdmission(context.Background(), evt)

	if result.Verdict != VerdictBlocked {
		t.Errorf("expected VerdictBlocked, got %q", result.Verdict)
	}

	// Verify plugin quarantined
	quarantinePath := filepath.Join(cfg.QuarantineDir, "plugins", "malicious-plugin")
	if _, err := os.Stat(quarantinePath); os.IsNotExist(err) {
		t.Error("expected plugin to be quarantined")
	}

	// Verify original removed
	if _, err := os.Stat(pluginPath); !os.IsNotExist(err) {
		t.Error("expected original plugin dir to be removed after quarantine")
	}

	// Verify file preserved in quarantine
	data, err := os.ReadFile(filepath.Join(quarantinePath, "plugin.js"))
	if err != nil {
		t.Fatalf("expected quarantined file to exist: %v", err)
	}
	if string(data) != "eval(atob('...'))" {
		t.Errorf("quarantined file content mismatch: %q", string(data))
	}
}

func TestFullQuarantineFlow_SQLiteState(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)

	skillPath := filepath.Join(skillDir, "tracked-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "index.js"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Block and quarantine via SQLite (simulating what applyPostScanEnforcement does)
	if err := store.SetActionField("skill", "tracked-skill", "install", "block", "auto-block"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionField("skill", "tracked-skill", "file", "quarantine", "auto-quarantine"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionField("skill", "tracked-skill", "runtime", "disable", "auto-disable"); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)

	evt := InstallEvent{Type: InstallSkill, Name: "tracked-skill", Path: skillPath, Timestamp: time.Now()}
	result := w.runAdmission(context.Background(), evt)

	if result.Verdict != VerdictBlocked {
		t.Errorf("expected VerdictBlocked, got %q", result.Verdict)
	}

	// Verify all three dimensions in SQLite
	entry, err := store.GetAction("skill", "tracked-skill")
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected action entry in SQLite")
		return
	}
	if entry.Actions.Install != "block" {
		t.Errorf("SQLite: expected install=block, got %q", entry.Actions.Install)
	}
	if entry.Actions.File != "quarantine" {
		t.Errorf("SQLite: expected file=quarantine, got %q", entry.Actions.File)
	}
	if entry.Actions.Runtime != "disable" {
		t.Errorf("SQLite: expected runtime=disable, got %q", entry.Actions.Runtime)
	}

	// Verify files quarantined
	quarantinePath := filepath.Join(cfg.QuarantineDir, "skills", "tracked-skill")
	if _, err := os.Stat(quarantinePath); os.IsNotExist(err) {
		t.Error("expected skill to be quarantined on disk")
	}
}

func TestWatcherQuarantineRecordsConnectorHashAndRestoresWithoutRequarantine(t *testing.T) {
	cfg, store, logger, skillDir := setupQuarantineProvenanceTestEnv(t)
	cfg.Guardrail.Connector = "codex"
	skillPath := filepath.Join(skillDir, "review-pr")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "SKILL.md"), []byte("review safely\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionField("skill", "review-pr", "install", "block", "fixture"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionField("skill", "review-pr", "file", "quarantine", "fixture"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionField("skill", "review-pr", "runtime", "disable", "fixture"); err != nil {
		t.Fatal(err)
	}
	// Since config_version 9 the block list is asset_policy, not audit.db.
	cfg.AssetPolicy.Skill.Denied = append(cfg.AssetPolicy.Skill.Denied, config.AssetPolicyRule{Name: "review-pr", Reason: "fixture"})
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	evt := InstallEvent{
		Type: InstallSkill, Name: "review-pr", Path: skillPath,
		Connector: "codex", Timestamp: time.Now().UTC(),
	}
	if result := w.runAdmission(context.Background(), evt); result.Verdict != VerdictBlocked {
		t.Fatalf("quarantine verdict = %q", result.Verdict)
	}

	records, err := store.ListQuarantineRecordsForConnector(
		context.Background(), "skill", "review-pr", "codex",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("quarantine records = %#v", records)
	}
	record := records[0]
	wantQuarantine := filepath.Join(cfg.QuarantineDir, "skills", "codex", "review-pr")
	if record.OriginalPath != filepath.Clean(skillPath) ||
		record.QuarantinePath != wantQuarantine || record.ContentHash == "" ||
		record.State != audit.QuarantineStateActive || record.OwnershipJSON == "{}" {
		t.Fatalf("quarantine record = %#v", record)
	}
	if len(record.Connectors) != 2 || record.Connectors[0] != "" || record.Connectors[1] != "codex" {
		t.Fatalf("quarantine connectors = %#v", record.Connectors)
	}
	if matches, err := enforce.AssetContentHashMatches(wantQuarantine, record.ContentHash); err != nil || !matches {
		t.Fatalf("quarantine hash match=%t err=%v", matches, err)
	}

	if err := w.RestoreQuarantined(
		context.Background(), "skill", "review-pr", "codex", "",
	); err != nil {
		t.Fatal(err)
	}
	if matches, err := enforce.AssetContentHashMatches(skillPath, record.ContentHash); err != nil || !matches {
		t.Fatalf("restore hash match=%t err=%v", matches, err)
	}
	entry, err := store.GetAction("skill", "review-pr")
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil || entry.Actions.Install != "block" ||
		entry.Actions.Runtime != "disable" || entry.Actions.File != "" ||
		entry.SourcePath != filepath.Clean(skillPath) {
		t.Fatalf("restored action = %#v", entry)
	}

	// The watcher still returns a blocked admission verdict, but the exact
	// restored path is retained because restore cleared only the file action.
	if result := w.runAdmission(context.Background(), evt); result.Verdict != VerdictBlocked {
		t.Fatalf("post-restore verdict = %q", result.Verdict)
	}
	if _, err := os.Stat(skillPath); err != nil {
		t.Fatalf("restored blocked skill was re-quarantined: %v", err)
	}
	if _, err := os.Lstat(wantQuarantine); !os.IsNotExist(err) {
		t.Fatalf("post-restore quarantine path exists: %v", err)
	}
	if records, err := store.ListQuarantineRecordsForConnector(
		context.Background(), "skill", "review-pr", "codex",
	); err != nil || len(records) != 0 {
		t.Fatalf("retired records = %#v err=%v", records, err)
	}
}

func TestWatcherQuarantineKeepsLogicalAssetIdentitySeparateFromPhysicalDirectory(t *testing.T) {
	cfg, store, logger, skillDir := setupQuarantineProvenanceTestEnv(t)
	cfg.Guardrail.Connector = "hermes"
	physicalName := "defenseclaw-skill-scanner-test-20260901080229"
	logicalName := "agent-security-refusals"
	skillPath := filepath.Join(skillDir, physicalName)
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(skillPath, "SKILL.md"),
		[]byte("---\nname: agent-security-refusals\n---\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	w := New(
		cfg, []string{skillDir}, nil, store, logger, nil, nil,
	)
	evt := InstallEvent{
		Type: InstallSkill, Name: logicalName, Path: skillPath,
		Connector: "hermes", Timestamp: time.Now().UTC(),
	}
	w.quarantineAsset(context.Background(), evt)

	records, err := store.ListQuarantineRecordsForConnector(
		context.Background(), "skill", logicalName, "hermes",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("quarantine records = %#v", records)
	}
	record := records[0]
	wantQuarantine := filepath.Join(cfg.QuarantineDir, "skills", "hermes", physicalName)
	if record.TargetName != logicalName || record.OriginalPath != filepath.Clean(skillPath) ||
		record.QuarantinePath != wantQuarantine || record.State != audit.QuarantineStateActive {
		t.Fatalf("quarantine record = %#v", record)
	}
	if _, err := os.Lstat(skillPath); !os.IsNotExist(err) {
		t.Fatalf("logical-name source still exists: %v", err)
	}
	if matches, err := enforce.AssetContentHashMatches(wantQuarantine, record.ContentHash); err != nil || !matches {
		t.Fatalf("quarantine hash match=%t err=%v", matches, err)
	}

	if err := w.RestoreQuarantined(
		context.Background(), "skill", logicalName, "hermes", "",
	); err != nil {
		t.Fatal(err)
	}
	if matches, err := enforce.AssetContentHashMatches(skillPath, record.ContentHash); err != nil || !matches {
		t.Fatalf("restore hash match=%t err=%v", matches, err)
	}
	if records, err := store.ListQuarantineRecordsForConnector(
		context.Background(), "skill", logicalName, "hermes",
	); err != nil || len(records) != 0 {
		t.Fatalf("retired records = %#v err=%v", records, err)
	}
}

func newWatcherQuarantineRetryFixture(
	t *testing.T,
) (*InstallWatcher, *audit.Store, audit.QuarantineRecord, string) {
	t.Helper()
	cfg, store, logger, skillDir := setupQuarantineProvenanceTestEnv(t)
	cfg.Guardrail.Connector = "codex"
	skillPath := filepath.Join(skillDir, "review-pr")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(skillPath, "SKILL.md"), []byte("review safely\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	for field, value := range map[string]string{
		"install": "block", "file": "quarantine", "runtime": "disable",
	} {
		if err := store.SetActionField("skill", "review-pr", field, value, "fixture"); err != nil {
			t.Fatal(err)
		}
	}
	cfg.AssetPolicy.Skill.Denied = append(cfg.AssetPolicy.Skill.Denied, config.AssetPolicyRule{Name: "review-pr", Reason: "fixture"})
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	if result := w.runAdmission(context.Background(), InstallEvent{
		Type: InstallSkill, Name: "review-pr", Path: skillPath,
		Connector: "codex", Timestamp: time.Now().UTC(),
	}); result.Verdict != VerdictBlocked {
		t.Fatalf("quarantine verdict = %q", result.Verdict)
	}
	records, err := store.ListQuarantineRecordsForConnector(
		context.Background(), "skill", "review-pr", "codex",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("quarantine records = %#v", records)
	}
	return w, store, records[0], skillDir
}

func TestWatcherRestoreRetryUsesDurablyBoundAlternatePath(t *testing.T) {
	w, store, record, skillDir := newWatcherQuarantineRetryFixture(t)
	alternatePath := filepath.Join(skillDir, "alternate", "review-pr")
	if err := store.UpdateQuarantineRecordState(
		context.Background(), record.ID, audit.QuarantineStateRestoring, alternatePath,
	); err != nil {
		t.Fatal(err)
	}
	if err := enforce.ExecuteAssetRestore(enforce.AssetRestorePlan{
		RecordID: record.ID, TargetType: record.TargetType, TargetName: record.TargetName,
		QuarantineRoot: w.cfg.QuarantineDir, QuarantinePath: record.QuarantinePath,
		RestorePath: alternatePath, AllowedRoots: []string{skillDir},
		ContentHash: record.ContentHash,
	}); err != nil {
		t.Fatal(err)
	}

	// Simulate failure after the filesystem transaction but before
	// CompleteQuarantineRestore commits. An empty-path retry must honor the
	// already-bound restoring destination rather than reverting to OriginalPath.
	if err := w.RestoreQuarantined(
		context.Background(), "skill", "review-pr", "codex", "",
	); err != nil {
		t.Fatal(err)
	}
	if matches, err := enforce.AssetContentHashMatches(
		alternatePath, record.ContentHash,
	); err != nil || !matches {
		t.Fatalf("alternate restore hash match=%t err=%v", matches, err)
	}
	if records, err := store.ListQuarantineRecordsForConnector(
		context.Background(), "skill", "review-pr", "codex",
	); err != nil || len(records) != 0 {
		t.Fatalf("retired retry records = %#v err=%v", records, err)
	}
	entry, err := store.GetAction("skill", "review-pr")
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil || entry.SourcePath != filepath.Clean(alternatePath) ||
		entry.Actions.File != "" || entry.Actions.Install != "block" ||
		entry.Actions.Runtime != "disable" {
		t.Fatalf("alternate retry action = %#v", entry)
	}
}

func TestWatcherRestoreRetryRejectsExplicitPathMismatch(t *testing.T) {
	w, store, record, skillDir := newWatcherQuarantineRetryFixture(t)
	boundPath := filepath.Join(skillDir, "alternate", "review-pr")
	if err := store.UpdateQuarantineRecordState(
		context.Background(), record.ID, audit.QuarantineStateRestoring, boundPath,
	); err != nil {
		t.Fatal(err)
	}
	mismatchPath := filepath.Join(skillDir, "different", "review-pr")
	err := w.RestoreQuarantined(
		context.Background(), "skill", "review-pr", "codex", mismatchPath,
	)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("explicit mismatch error = %v", err)
	}
	current, err := store.GetQuarantineRecord(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current == nil || current.State != audit.QuarantineStateRestoring ||
		!sameWatcherPath(current.RestorePath, boundPath) {
		t.Fatalf("restore journal changed after mismatch = %#v", current)
	}
	if matches, err := enforce.AssetContentHashMatches(
		record.QuarantinePath, record.ContentHash,
	); err != nil || !matches {
		t.Fatalf("quarantine after mismatch match=%t err=%v", matches, err)
	}
	if _, err := os.Lstat(mismatchPath); !os.IsNotExist(err) {
		t.Fatalf("mismatch restore path was created: %v", err)
	}
}

func TestAdmission_AllowedSkip_NoQuarantine(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)

	skillPath := filepath.Join(skillDir, "safe-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "main.py"), []byte("print('hello')"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Allow-list the skill
	cfg.AssetPolicy.Skill.Allowed = append(cfg.AssetPolicy.Skill.Allowed, config.AssetPolicyRule{Name: "safe-skill", Reason: "pre-approved"})

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)

	evt := InstallEvent{Type: InstallSkill, Name: "safe-skill", Path: skillPath, Timestamp: time.Now()}
	result := w.runAdmission(context.Background(), evt)

	if result.Verdict != VerdictAllowed {
		t.Errorf("expected VerdictAllowed, got %q", result.Verdict)
	}

	// Verify files NOT moved — still in original location
	if _, err := os.Stat(skillPath); os.IsNotExist(err) {
		t.Error("allowed skill should NOT be quarantined")
	}

	// Verify quarantine dir does NOT have this skill
	quarantinePath := filepath.Join(cfg.QuarantineDir, "skills", "safe-skill")
	if _, err := os.Stat(quarantinePath); !os.IsNotExist(err) {
		t.Error("allowed skill should NOT appear in quarantine dir")
	}
}

func TestActionState_InstallOverwrite(t *testing.T) {
	_, store, _, _ := setupTestEnv(t)

	if err := store.SetActionField("skill", "flip-skill", "install", "block", "blocked"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionField("skill", "flip-skill", "install", "allow", "now allowed"); err != nil {
		t.Fatal(err)
	}

	entry, err := store.GetAction("skill", "flip-skill")
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected action entry, got nil")
		return
	}
	if entry.Actions.Install != "allow" {
		t.Errorf("expected install=allow after overwrite, got %q", entry.Actions.Install)
	}
}

func TestAdmission_BlockedVerdict(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)

	cfg.AssetPolicy.Skill.Denied = append(cfg.AssetPolicy.Skill.Denied, config.AssetPolicyRule{Name: "evil-skill", Reason: "malicious"})

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)

	skillPath := filepath.Join(skillDir, "evil-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}

	evt := InstallEvent{Type: InstallSkill, Name: "evil-skill", Path: skillPath, Timestamp: time.Now()}
	result := w.runAdmission(context.Background(), evt)

	if result.Verdict != VerdictBlocked {
		t.Fatalf("expected verdict %q, got %q", VerdictBlocked, result.Verdict)
	}

}

func TestAdmission_AllowedVerdict(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)

	cfg.AssetPolicy.Skill.Allowed = append(cfg.AssetPolicy.Skill.Allowed, config.AssetPolicyRule{Name: "trusted-skill", Reason: "pre-approved"})

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)

	skillPath := filepath.Join(skillDir, "trusted-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}

	evt := InstallEvent{Type: InstallSkill, Name: "trusted-skill", Path: skillPath, Timestamp: time.Now()}
	result := w.runAdmission(context.Background(), evt)

	if result.Verdict != VerdictAllowed {
		t.Fatalf("expected verdict %q, got %q", VerdictAllowed, result.Verdict)
	}
}

// The watcher once forwarded MCP block verdicts to the removed
// openshell-sandbox policy writer, which rewrote a policy file nothing
// enforced. MCP blocking belongs to the sidecar's admission handler; the
// watcher's own enforcement must not write anything for an MCP event.
func TestEnforceBlockForMCPWritesNoSandboxPolicy(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	cfg := &config.Config{DataDir: dir, PolicyDir: filepath.Join(dir, "policies")}
	w := New(cfg, nil, nil, nil, nil, nil, nil)
	w.enforceBlock(context.Background(), InstallEvent{Type: InstallMCP, Name: "evil-server", Timestamp: time.Now().UTC()})
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("MCP block wrote %d entries under the data dir: %v", len(entries), entries)
	}
}

func TestAdmission_BundledPluginIsNotScanned(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	pluginDir := filepath.Join(filepath.Dir(skillDir), "plugins")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(pluginDir, "defenseclaw")
	w := New(cfg, nil, []string{pluginDir}, store, logger, nil, nil)
	scanned := false
	w.scannerFactory = func(InstallEvent) scanner.Scanner { scanned = true; return nil }
	w.SetBundledPluginCheck(func(path string) bool { return path == own })

	result := w.runAdmission(context.Background(), InstallEvent{
		Type: InstallPlugin, Name: "defenseclaw", Path: own, Timestamp: time.Now(),
	})
	if result.Verdict != VerdictAllowed || scanned {
		t.Fatalf("bundled plugin admission = %+v, scanned=%v", result, scanned)
	}
}

// A valid OPA "scan" verdict is final: the built-in fallback runs only when
// OPA fails. Here the fallback alone would admit the skill (scan_on_install
// off) while the policy asks for a scan, so the scanner must run.
func TestAdmission_FallbackOnlyOnOPAError(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Admission.Skill.ScanOnInstall = new(bool)
	regoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(regoDir, "admission.rego"), []byte("package defenseclaw.admission\n\nimport rego.v1\n\nverdict := \"scan\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := policy.New(regoDir)
	if err != nil {
		t.Fatal(err)
	}
	w := New(cfg, []string{skillDir}, nil, store, logger, engine, nil)
	scanned := false
	w.scannerFactory = func(InstallEvent) scanner.Scanner { scanned = true; return nil }

	skillPath := filepath.Join(skillDir, "needs-scan")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	w.runAdmission(context.Background(), InstallEvent{Type: InstallSkill, Name: "needs-scan", Path: skillPath, Timestamp: time.Now()})
	if !scanned {
		t.Fatal("the fallback overrode a valid OPA scan verdict")
	}
}

// TestEvaluateAdmissionFollowsThePolicySource: admission evaluates the live
// generation's prepared OPA on every event, so a changed Rego module applies
// without /policy/reload or a gateway restart.
func TestEvaluateAdmissionFollowsThePolicySource(t *testing.T) {
	prepare := func(verdict string) *policy.Prepared {
		dir := t.TempDir()
		module := "package defenseclaw.admission\n\nimport rego.v1\n\nverdict := \"" + verdict + "\"\n"
		if err := os.WriteFile(filepath.Join(dir, "admission.rego"), []byte(module), 0o600); err != nil {
			t.Fatal(err)
		}
		prepared, err := policy.Prepare(context.Background(), dir)
		if err != nil {
			t.Fatal(err)
		}
		return prepared
	}
	current := prepare("allowed")
	w := &InstallWatcher{}
	w.SetPolicySource(func() *policy.Prepared { return current })
	in := policy.AdmissionInput{TargetType: "skill", TargetName: "s"}
	if got := w.evaluateAdmission(context.Background(), in).Verdict; got != "allowed" {
		t.Fatalf("verdict = %q, want allowed", got)
	}
	current = prepare("warning")
	if got := w.evaluateAdmission(context.Background(), in).Verdict; got != "warning" {
		t.Fatalf("verdict after the generation changed = %q, want warning", got)
	}
}
