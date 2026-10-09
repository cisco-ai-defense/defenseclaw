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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
		Watch: config.WatchConfig{DebounceMs: 100, AutoBlock: true},
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

// GAP-0964: in mode observe a skill outside the approved catalog is admitted
// with an asset-policy row that says it would be blocked in mode action.
func TestAdmission_ObserveRegistryWritesWouldBlockRow(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	runtime := &watcherTestRuntime{}
	logger.SetRuntimeV8Emitter(runtime)
	cfg.AssetPolicy.Enabled, cfg.AssetPolicy.Mode = true, config.AssetPolicyModeObserve
	cfg.AssetPolicy.Skill.RegistryRequired = true
	cfg.AssetPolicy.Skill.Registry = []config.AssetPolicyRule{{Name: "epa-notes-r1", Reason: "registry:acme-catalog"}}
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	skillPath := filepath.Join(skillDir, "epa-two-r1")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	result := w.runAdmission(context.Background(), InstallEvent{Type: InstallSkill, Name: "epa-two-r1", Path: skillPath, Timestamp: time.Now()})
	if strings.Contains(result.Reason, "approved registry") {
		t.Fatalf("verdict %q (%s), want the catalog rule not to block in mode observe", result.Verdict, result.Reason)
	}
	logs, _ := runtime.snapshot()
	var seen []string
	for _, record := range logs {
		data, err := record.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "would_block=true") && strings.Contains(string(data), "source=registry-required") {
			return
		}
		seen = append(seen, record.Action())
	}
	t.Fatalf("no would-block asset-policy row for epa-two-r1; records: %v", seen)
}

// GAP-0581: a copy of a denied skill in a folder with another name, whose
// SKILL.md still declares the denied name, is refused like the original.
func TestAdmission_BlockedSkillByDeclaredName(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.AssetPolicy.Skill.Denied = append(cfg.AssetPolicy.Skill.Denied, config.AssetPolicyRule{Name: "epa-deny"})
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)

	skillPath := filepath.Join(skillDir, "epa-alias")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "SKILL.md"), []byte("---\nname: epa-deny\ndescription: lab\n---\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := w.runAdmission(context.Background(), InstallEvent{Type: InstallSkill, Name: "epa-alias", Path: skillPath, Timestamp: time.Now()})
	if result.Verdict != VerdictBlocked {
		t.Fatalf("verdict %q (%s), want blocked", result.Verdict, result.Reason)
	}
}

// GAP-0778: a Claude Code marketplace plugin, which the watcher names
// plugin@marketplace from a folder named for its version, is refused by a
// denied rule with the plugin name an administrator writes.
func TestAdmission_BlockedMarketplacePluginByPluginName(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.AssetPolicy.Plugin.Denied = append(cfg.AssetPolicy.Plugin.Denied, config.AssetPolicyRule{Name: "rvw8p"})
	cache := filepath.Join(t.TempDir(), "plugins", "cache")
	version := filepath.Join(cache, "rvw8mkt", "rvw8p", "1.0.0")
	if err := os.MkdirAll(version, 0o700); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, nil, []string{cache}, store, logger, nil, nil)
	result := w.runAdmission(context.Background(), InstallEvent{Type: InstallPlugin, Name: "rvw8p@rvw8mkt", Path: version, Timestamp: time.Now()})
	if result.Verdict != VerdictBlocked || !strings.Contains(result.Reason, "denied by asset policy") {
		t.Fatalf("verdict %q (%s), want blocked by the denied rule before any scan", result.Verdict, result.Reason)
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
	if err := os.WriteFile(filepath.Join(skillDir, "new-skill", "SKILL.md"), []byte("# new\n"), 0o600); err != nil {
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

// deadlineScanner records how long the scan context it was given has left.
type deadlineScanner struct {
	countingScanner
	remaining time.Duration
}

func (s *deadlineScanner) Scan(ctx context.Context, target string) (*scanner.ScanResult, error) {
	if d, ok := ctx.Deadline(); ok {
		s.remaining = time.Until(d)
	}
	return s.countingScanner.Scan(ctx, target)
}

// A skill scan runs for scanners.skill_scanner.timeouts.scan_s in the install
// watcher and in the rescan: a fixed five minutes cut off every scan an
// administrator had allowed longer. Plugin and MCP scans keep five minutes.
func TestSkillScanFollowsScanS(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Scanners.SkillScanner.Timeouts.ScanS = 900
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	fake := &deadlineScanner{countingScanner: countingScanner{name: "skill-scanner"}}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return fake }

	skillPath := filepath.Join(skillDir, "large-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	evt := InstallEvent{Type: InstallSkill, Name: "large-skill", Path: skillPath, Timestamp: time.Now()}

	w.runAdmission(context.Background(), evt)
	if fake.calls != 1 || fake.remaining < 14*time.Minute {
		t.Fatalf("admission scan: calls=%d, time left=%s; want 1 call with about 15m", fake.calls, fake.remaining)
	}
	fake.remaining = 0
	w.scanAndEmit(context.Background(), evt)
	if fake.calls != 2 || fake.remaining < 14*time.Minute {
		t.Fatalf("rescan: calls=%d, time left=%s; want 2 calls with about 15m", fake.calls, fake.remaining)
	}
	if got := w.scanTimeout(InstallEvent{Type: InstallPlugin}); got != 5*time.Minute {
		t.Fatalf("plugin scan timeout = %s, want 5m", got)
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

// GAP-0376: with the judge unreachable the scanner finishes with its static
// analyzers and reports an INFO LLM_ANALYSIS_FAILED finding. Admission read
// that as a MEDIUM warning and left the skill loaded; the scan now fails
// closed and says why on the quarantine record.
func TestAdmissionFailsClosedWhenTheJudgeDidNotRun(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	fake := &countingScanner{name: "skill-scanner", findings: []scanner.Finding{
		{ID: "m1", RuleID: "DATA-READ", Severity: scanner.SeverityMedium, Title: "reads shell history"},
		{ID: "llm", RuleID: scanner.RuleLLMAnalysisFailed, Severity: scanner.SeverityInfo, Title: "LLM analysis failed",
			Description: "The LLM analyzer encountered an error: APIConnectionError"},
	}}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return fake }
	skillPath := filepath.Join(skillDir, "usage-stats")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	res := w.runAdmission(context.Background(), InstallEvent{Type: InstallSkill, Name: "usage-stats", Path: skillPath, Timestamp: time.Now()})
	if res.Verdict != VerdictBlocked || !strings.Contains(res.Reason, "the LLM judge did not run") {
		t.Fatalf("verdict %q reason %q, want blocked because the judge did not run", res.Verdict, res.Reason)
	}
	if _, err := os.Lstat(skillPath); !os.IsNotExist(err) {
		t.Fatalf("the skill stayed in place (lstat err %v)", err)
	}
	records, err := store.ListQuarantineRecordsForConnector(context.Background(), "skill", "usage-stats", "")
	if err != nil || len(records) != 1 || !strings.Contains(records[0].Reason, "the LLM judge did not run") {
		t.Fatalf("quarantine records %+v (err %v), want one naming the judge failure", records, err)
	}
}

// GAP-0393: quarantining Claude Code's skill-creator recorded the block and
// the runtime disable for every connector, so Codex's vendor-bundled
// skill-creator read as quarantined and disabled. The rows now belong to the
// connector that holds the copy.
func TestAutomaticEnforcementIsScopedToTheConnectorWithTheCopy(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Gateway.Watcher.Skill.TakeAction = true
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	w.SetRootConnectors(map[string]string{skillDir: "claudecode"})
	w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &countingScanner{name: "skill-scanner", findings: []scanner.Finding{
			{ID: "c1", RuleID: "CMD-INJECTION", Severity: scanner.SeverityCritical, Title: "command injection"},
		}}
	}
	skillPath := filepath.Join(skillDir, "skill-creator")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	res := w.runAdmission(context.Background(), InstallEvent{Type: InstallSkill, Name: "skill-creator", Path: skillPath, Timestamp: time.Now()})
	if res.Verdict != VerdictRejected {
		t.Fatalf("verdict %q, want rejected", res.Verdict)
	}
	pe := enforce.NewPolicyEngine(store)
	if disabled, _ := pe.IsDisabledForConnector("skill", "skill-creator", "claudecode"); !disabled {
		t.Fatal("claudecode copy is not disabled")
	}
	if disabled, _ := pe.IsDisabledForConnector("skill", "skill-creator", "codex"); disabled {
		t.Fatal("the claudecode verdict disabled codex's skill-creator too")
	}
}

// GAP-0394: a skill folder that is a symlink was reported quarantined while
// quarantine refused the link and left it in place, and a quarantine that
// failed (an unwritable quarantine folder) also read as quarantined. The link
// is now removed (its target untouched) and a failed move says so.
func TestLinkedOrUnmovableSkillReportsWhatHappened(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows; junctions take the same path")
	}
	admit := func(t *testing.T, prepare func(cfg *config.Config, skillDir string) string) (*audit.ActionEntry, string) {
		cfg, store, logger, skillDir := setupTestEnv(t)
		cfg.Gateway.Watcher.Skill.TakeAction = true
		w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
		w.scannerFactory = func(InstallEvent) scanner.Scanner {
			return &countingScanner{name: "skill-scanner", findings: []scanner.Finding{
				{ID: "c1", RuleID: "SEC-AWS-KEY", Severity: scanner.SeverityCritical, Title: "hardcoded key"},
			}}
		}
		path := prepare(cfg, skillDir)
		w.runAdmission(context.Background(), InstallEvent{Type: InstallSkill, Name: filepath.Base(path), Path: path, Timestamp: time.Now()})
		entry, err := store.GetAction("skill", filepath.Base(path))
		if err != nil || entry == nil {
			t.Fatalf("no journal row (err %v)", err)
		}
		return entry, path
	}
	t.Run("link", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "linked-high-src")
		if err := os.MkdirAll(target, 0o700); err != nil {
			t.Fatal(err)
		}
		entry, path := admit(t, func(_ *config.Config, skillDir string) string {
			link := filepath.Join(skillDir, "linked-high")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return link
		})
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("the link stayed in the skills folder (lstat err %v)", err)
		}
		if _, err := os.Stat(target); err != nil {
			t.Fatalf("the link target was touched: %v", err)
		}
		if entry.Actions.File == "quarantine" || !strings.HasPrefix(entry.Reason, "link removed") {
			t.Fatalf("journal %+v reason %q, want link removed and no file quarantine", entry.Actions, entry.Reason)
		}
	})
	t.Run("unwritable quarantine", func(t *testing.T) {
		entry, path := admit(t, func(cfg *config.Config, skillDir string) string {
			if err := os.MkdirAll(cfg.QuarantineDir, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(cfg.QuarantineDir, 0o700) })
			dir := filepath.Join(skillDir, "aws-deploy")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			return dir
		})
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("expected the skill to stay in place: %v", err)
		}
		if entry.Actions.File == "quarantine" || entry.Actions.Install != "block" || entry.Actions.Runtime != "disable" ||
			!strings.HasPrefix(entry.Reason, "quarantine failed: ") {
			t.Fatalf("journal %+v reason %q, want blocked, disabled, quarantine failed", entry.Actions, entry.Reason)
		}
	})
}

// blockingScanner waits until its scan context ends and reports that.
type blockingScanner struct{ countingScanner }

func (s *blockingScanner) Scan(ctx context.Context, target string) (*scanner.ScanResult, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// GAP-0335: a watcher restart (config reload) or a gateway stop cancels the
// watcher's context; the in-flight install scan failed closed as a scanner
// failure and quarantined a clean skill. A scan that times out still does.
func TestScanCutOffByTheWatcherStoppingDoesNotQuarantine(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &blockingScanner{} }
	skillPath := filepath.Join(skillDir, "slow-scan")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	evt := InstallEvent{Type: InstallSkill, Name: "slow-scan", Path: skillPath, Timestamp: time.Now()}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	res := w.runAdmission(ctx, evt)
	if !res.Interrupted || res.Verdict == VerdictBlocked {
		t.Fatalf("watcher stop: result %+v, want interrupted and not blocked", res)
	}
	if _, err := os.Lstat(skillPath); err != nil {
		t.Fatalf("watcher stop quarantined the skill: %v", err)
	}

	cfg.Scanners.SkillScanner.Timeouts.ScanS = 1
	res = w.runAdmission(context.Background(), evt)
	if res.Interrupted || res.Verdict != VerdictBlocked {
		t.Fatalf("scan timeout: result %+v, want blocked (fail-closed)", res)
	}
}

// failingScanner fails every scan the way a crashed scanner does.
type failingScanner struct{ countingScanner }

func (s *failingScanner) Scan(context.Context, string) (*scanner.ScanResult, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return nil, fmt.Errorf("%s exited 1", s.name)
}

// GAP-0662, GAP-0825: a scan that fails blocks the asset and disables it at
// runtime for its connector, as a rejected verdict does: the hook refuses a
// blocked MCP server, and a skill the gateway could not move out does not
// load. The next scan that succeeds releases it.
func TestScanFailureDisablesTheAssetAtRuntime(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &failingScanner{countingScanner{name: "mcp-scanner"}} }
	evt := InstallEvent{Type: InstallMCP, Name: "notes", Path: "mcp:codex:notes", Connector: "codex", Timestamp: time.Now()}
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked || res.RuntimeAction != "block" {
		t.Fatalf("failed scan: result %+v, want blocked with a runtime block", res)
	}
	entry, err := store.GetActionForConnector("mcp", "notes", "codex")
	if err != nil || entry == nil || entry.Actions.Install != "block" || entry.Actions.Runtime != "disable" {
		t.Fatalf("journal %+v (err %v), want install block and runtime disable for codex", entry, err)
	}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "mcp-scanner"} }
	if res := w.runAdmission(context.Background(), evt); res.Verdict == VerdictBlocked {
		t.Fatalf("clean scan: result %+v, want the block released", res)
	}
	if entry, err := store.GetActionForConnector("mcp", "notes", "codex"); err != nil || (entry != nil && !entry.Actions.IsEmpty()) {
		t.Fatalf("journal after a clean scan %+v (err %v), want no block", entry, err)
	}
}

// readingScanner fails a scan of a folder it may not list, as the skill
// scanner exits 1 on one the gateway service cannot read.
type readingScanner struct{ countingScanner }

func (s *readingScanner) Scan(ctx context.Context, target string) (*scanner.ScanResult, error) {
	if _, err := os.ReadDir(target); err != nil {
		return nil, err
	}
	return s.countingScanner.Scan(ctx, target)
}

// GAP-0825: a skill folder moved into a watched folder keeps the access list
// of where it came from, so the gateway could not read it, the scan failed
// and the CRITICAL skill stayed. The watcher asks for read access (the hook
// guardian on a managed Windows computer) and scans again.
func TestUnreadableSkillIsScannedAfterReadGrant(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions that bind the test user")
	}
	cfg, store, logger, skillDir := setupTestEnv(t)
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &readingScanner{countingScanner{name: "skill-scanner"}} }
	moved := filepath.Join(skillDir, "moved-in")
	if err := os.MkdirAll(moved, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(moved, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(moved, 0o700) })
	grants := 0
	enforce.SetAssetReadGranter(func(targetType, path string) error {
		grants++
		if targetType != "skill" || path != moved {
			return fmt.Errorf("unexpected grant %s %s", targetType, path)
		}
		return os.Chmod(path, 0o700)
	})
	t.Cleanup(func() { enforce.SetAssetReadGranter(nil) })
	res := w.runAdmission(context.Background(), InstallEvent{Type: InstallSkill, Name: "moved-in", Path: moved, Timestamp: time.Now()})
	if grants != 1 || res.Verdict == VerdictBlocked {
		t.Fatalf("grants=%d result %+v, want one grant and the scan admitted", grants, res)
	}
}

// GAP-0826: a quarantine that failed (the disk was full) left the CRITICAL
// skill in its folder with nothing retrying it. The watcher records the
// unfinished admission with its account, admits it again once due, and
// forgets it when the quarantine completes.
func TestFailedQuarantineIsRecordedAndRetried(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a quarantine folder the test user may not write")
	}
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Gateway.Watcher.Skill.TakeAction = true
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	w.SetAssetOwners([]AssetOwner{{Home: filepath.Dir(skillDir), Name: "dcw-std1"}})
	w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &countingScanner{name: "skill-scanner", findings: []scanner.Finding{
			{ID: "c1", RuleID: "SEC-AWS-KEY", Severity: scanner.SeverityCritical, Title: "hardcoded key"},
		}}
	}
	if err := os.MkdirAll(cfg.QuarantineDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfg.QuarantineDir, 0o700) })
	path := filepath.Join(skillDir, "crit-k")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	evt := InstallEvent{Type: InstallSkill, Name: "crit-k", Path: path, Timestamp: time.Now()}
	w.runAdmission(context.Background(), evt)
	issues, err := ReadAdmissionIssues(cfg.DataDir)
	if err != nil || len(issues) != 1 || issues[0].Kind != AdmissionNotQuarantined || issues[0].Account != "dcw-std1" {
		t.Fatalf("issues %+v (err %v), want one not-quarantined issue of dcw-std1", issues, err)
	}
	if due := w.state.dueIssues(time.Now(), AdmissionNotQuarantined); len(due) != 0 {
		t.Fatalf("due at once: %+v", due)
	}
	due := w.state.dueIssues(time.Now().Add(admissionRetryFirst), AdmissionNotQuarantined)
	if len(due) != 1 || due[0].Path != path {
		t.Fatalf("due after the first delay: %+v", due)
	}
	if err := os.Chmod(cfg.QuarantineDir, 0o700); err != nil {
		t.Fatal(err)
	}
	w.runAdmission(context.Background(), evt)
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("the retried quarantine left the skill in place: %v", err)
	}
	if issues, err := ReadAdmissionIssues(cfg.DataDir); err != nil || len(issues) != 0 {
		t.Fatalf("issues after the quarantine completed: %+v (err %v)", issues, err)
	}
}

// gateScanner holds every scan until release is closed and records the
// largest number of scans that ran at once.
type gateScanner struct {
	countingScanner
	release chan struct{}
	running int
	peak    int
}

func (s *gateScanner) Scan(ctx context.Context, target string) (*scanner.ScanResult, error) {
	s.mu.Lock()
	s.running++
	if s.running > s.peak {
		s.peak = s.running
	}
	s.mu.Unlock()
	<-s.release
	s.mu.Lock()
	s.running--
	s.mu.Unlock()
	return s.countingScanner.Scan(ctx, target)
}

// GAP-0341: 33 skills dropped at once were admitted one at a time, each one
// listed as ready and unscanned until its turn. Admission now runs a few at
// once and AdmissionStateFile shows the rest as pending or scanning.
func TestBulkDropIsAdmittedInParallelAndShownPending(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	gate := &gateScanner{countingScanner: countingScanner{name: "skill-scanner"}, release: make(chan struct{})}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return gate }
	for i := 0; i < 6; i++ {
		path := filepath.Join(skillDir, fmt.Sprintf("bulk-%d", i))
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte("# bulk\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		w.queuePending(path)
	}
	readState := func() map[string]string {
		raw, err := os.ReadFile(filepath.Join(cfg.DataDir, AdmissionStateFile))
		if err != nil {
			return nil
		}
		var doc admissionStateFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, a := range doc.Assets {
			out[a.Name] = a.State
		}
		return out
	}
	if st := readState(); len(st) != 6 || st["bulk-0"] != AdmissionPending {
		t.Fatalf("state before admission = %v, want 6 pending", st)
	}
	w.mu.Lock()
	for path := range w.pending {
		w.pending[path] = time.Now().Add(-time.Hour)
	}
	w.mu.Unlock()
	w.processPending(context.Background())
	deadline := time.Now().Add(5 * time.Second)
	for {
		gate.mu.Lock()
		running := gate.running
		gate.mu.Unlock()
		if running == liveAdmissionWorkers || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	scanning := 0
	for _, state := range readState() {
		if state == AdmissionScanning {
			scanning++
		}
	}
	close(gate.release)
	w.waitAdmissions()
	if gate.peak != liveAdmissionWorkers || scanning != liveAdmissionWorkers {
		t.Fatalf("peak concurrent scans %d, scanning entries %d; want %d", gate.peak, scanning, liveAdmissionWorkers)
	}
	if gate.calls != 6 {
		t.Fatalf("scans = %d, want 6", gate.calls)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, AdmissionStateFile)); !os.IsNotExist(err) {
		t.Fatalf("admission state file left after every admission ended (err %v)", err)
	}
}

// GAP-0418: the HIGH finding that quarantined a skill (a location-less
// analyzability finding) was missing from alerts; the watcher's block now
// names the deciding findings in its alert and journal reason.
func TestBlockReasonNamesTheDecidingFinding(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Gateway.Watcher.Skill.TakeAction = true
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &countingScanner{name: "skill-scanner", findings: []scanner.Finding{
			{ID: "m1", RuleID: "DATA-READ", Severity: scanner.SeverityMedium, Title: "reads files"},
			{ID: "h1", RuleID: "LOW_ANALYZABILITY", Severity: scanner.SeverityHigh, Title: "Critically low analyzability score"},
		}}
	}
	skillPath := filepath.Join(skillDir, "huge-blob")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	w.runAdmission(context.Background(), InstallEvent{Type: InstallSkill, Name: "huge-blob", Path: skillPath, Timestamp: time.Now()})
	entry, err := store.GetAction("skill", "huge-blob")
	if err != nil || entry == nil || !strings.Contains(entry.Reason, "LOW_ANALYZABILITY Critically low analyzability score") ||
		strings.Contains(entry.Reason, "DATA-READ") {
		t.Fatalf("journal %+v (err %v), want the reason to name only the HIGH finding", entry, err)
	}
}

// GAP-0575: a managed gateway's scan rows name the user whose folder held
// the asset and the judge model the scan ran with.
func TestWatcherScanCorrelationNamesOwnerAndJudge(t *testing.T) {
	home := t.TempDir()
	w := &InstallWatcher{}
	w.SetAssetOwners([]AssetOwner{{Home: home, ID: "S-1-5-21-1-1001", IDKind: "windows_sid", Name: "dcw-epw1"}})
	corr := w.ownedScanCorrelation(audit.ScanCorrelation{}, &scanner.ScanResult{
		Target: filepath.Join(home, ".claude", "skills", "epa-crit"), JudgeModel: "bedrock/haiku",
	})
	if corr.UserName != "dcw-epw1" || corr.UserID != "S-1-5-21-1-1001" || corr.UserIDKind != "windows_sid" || corr.JudgeModel != "bedrock/haiku" {
		t.Fatalf("correlation = %+v, want the owner and the judge", corr)
	}
	if other := w.ownedScanCorrelation(audit.ScanCorrelation{}, &scanner.ScanResult{Target: t.TempDir()}); other.UserName != "" || other.UserID != "" {
		t.Fatalf("an asset outside every enrolled home got an owner: %+v", other)
	}
}

// targetOnlyScanner finds a critical issue only when it scans real content:
// like the skill scanner, it does not follow a link at the root.
type targetOnlyScanner struct {
	countingScanner
	link string
}

func (s *targetOnlyScanner) Scan(ctx context.Context, target string) (*scanner.ScanResult, error) {
	result, err := s.countingScanner.Scan(ctx, target)
	if err == nil && target != s.link {
		result.Findings = []scanner.Finding{{ID: "c1", RuleID: "SEC-AWS-KEY", Severity: scanner.SeverityCritical, Title: "hardcoded key"}}
	}
	return result, err
}

// GAP-0394: a symlinked skill reached verdict allowed because the scanner
// scanned the link, not the folder the agent loads, and the rescan never
// listed it. It is scanned through its target, listed by the rescan, and the
// link is taken out.
func TestLinkedSkillIsScannedThroughItsTarget(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Gateway.Watcher.Skill.TakeAction = true
	target := filepath.Join(t.TempDir(), "linked-high-src")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(skillDir, "linked-high")
	if runtime.GOOS == "windows" {
		// A junction needs no privilege.
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
			t.Fatalf("mklink /J: %v %s", err, out)
		}
	} else if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &targetOnlyScanner{countingScanner: countingScanner{name: "skill-scanner"}, link: link}
	}
	listed := false
	for _, evt := range w.enumerateTargets() {
		listed = listed || evt.Path == link
	}
	if !listed {
		t.Fatal("the rescan does not list the linked skill")
	}
	res := w.runAdmission(context.Background(), InstallEvent{Type: InstallSkill, Name: "linked-high", Path: link, Timestamp: time.Now()})
	if res.Verdict == VerdictAllowed {
		t.Fatalf("verdict %s (%s), want the critical target blocked", res.Verdict, res.Reason)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("the link stayed in the skills folder (lstat err %v)", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("the link target was touched: %v", err)
	}
}

// GAP-0551: on a managed computer the hook guardian removes a quarantined
// original after admission, so admission wrote a rescan baseline while the
// folder was still there; the same skill copied back to that path later was
// skipped by the rescan as unchanged and stayed active. A quarantined path
// keeps no baseline, so the copy is admitted again.
func TestQuarantinedSkillCopiedBackIsAdmittedByTheRescan(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a folder the process cannot delete from")
	}
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Gateway.Watcher.Skill.TakeAction = true
	cfg.Watch.RescanEnabled = true
	cfg.Watch.RescanContentGated = true
	scans := &countingScanner{name: "skill-scanner", findings: []scanner.Finding{
		{ID: "c1", RuleID: "SEC-AWS-KEY", Severity: scanner.SeverityCritical, Title: "hardcoded key"},
	}}
	var verdicts []AdmissionResult
	watch := func() *InstallWatcher {
		w := New(cfg, []string{skillDir}, nil, store, logger, nil, func(r AdmissionResult) { verdicts = append(verdicts, r) })
		w.scannerFactory = func(InstallEvent) scanner.Scanner { return scans }
		return w
	}
	first := watch()
	first.runRescanCycle(context.Background()) // the root is covered
	path := filepath.Join(skillDir, "rvw-crit1")
	write := func() {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte("# rvw-crit1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	// The gateway cannot delete the original; the guardian removes it later.
	if err := os.Chmod(skillDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(skillDir, 0o700) })
	enforce.SetQuarantineSourceRemover(func(enforce.AssetQuarantinePlan, string) error { return nil })
	t.Cleanup(func() { enforce.SetQuarantineSourceRemover(nil) })
	evt := InstallEvent{Type: InstallSkill, Name: "rvw-crit1", Path: path, Timestamp: time.Now()}
	snap := first.admissionSnapshot(evt)
	res := first.runAdmission(context.Background(), evt)
	first.recordAdmissionBaseline(evt, snap, res)
	// A host upgraded from a build that wrote it still has that baseline.
	first.persistSnapshot(evt, snap, "scan-before-upgrade", first.scannerFingerprint(evt))
	if err := os.Chmod(skillDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(path); err != nil { // the guardian removal
		t.Fatal(err)
	}
	write() // the same skill, copied back
	before := scans.calls
	watch().runRescanCycle(context.Background())
	if scans.calls != before+1 || len(verdicts) != 1 || verdicts[0].Event.Path != path || verdicts[0].Verdict == VerdictAllowed {
		t.Fatalf("rescan scans %d (was %d), verdicts %+v: the copy put back was not admitted", scans.calls, before, verdicts)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("the copy put back was not quarantined (lstat err %v)", err)
	}
}

// GAP-0774: a skill rejected while take_action was false stayed installed
// and usable after take_action was turned back on, because its admission
// baseline let every rescan skip it as unchanged. Once take_action is on,
// the rescan admits it again and quarantines it; while it is off, the
// rescan does not scan it on every cycle.
func TestSkillRejectedWithTakeActionOffIsEnforcedOnceItIsOn(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Watch.RescanEnabled = true
	cfg.Watch.RescanContentGated = true
	scans := &countingScanner{name: "skill-scanner", findings: []scanner.Finding{
		{ID: "c1", RuleID: "SEC-AWS-KEY", Severity: scanner.SeverityCritical, Title: "hardcoded key"},
	}}
	watch := func(takeAction bool) *InstallWatcher {
		c := *cfg
		c.Gateway.Watcher.Skill.TakeAction = takeAction
		w := New(&c, []string{skillDir}, nil, store, logger, nil, nil)
		w.scannerFactory = func(InstallEvent) scanner.Scanner { return scans }
		return w
	}
	ctx := context.Background()
	observe := watch(false)
	observe.runRescanCycle(ctx) // the root is covered
	path := filepath.Join(skillDir, "epa-crit-e")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte("# epa-crit-e\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	evt := InstallEvent{Type: InstallSkill, Name: "epa-crit-e", Path: path, Timestamp: time.Now()}
	snap := observe.admissionSnapshot(evt)
	res := observe.runAdmission(ctx, evt)
	observe.recordAdmissionBaseline(evt, snap, res)
	before := scans.calls
	observe.runRescanCycle(ctx)
	if _, err := os.Lstat(path); res.Verdict != VerdictRejected || err != nil || scans.calls != before {
		t.Fatalf("take_action off: verdict %s, lstat err %v, rescan scans %d (was %d)", res.Verdict, err, scans.calls, before)
	}
	// Status reports the unenforced rejection until it is enforced.
	if issues, _ := ReadAdmissionIssues(cfg.DataDir); len(issues) != 1 || issues[0].Kind != AdmissionNotEnforced {
		t.Fatalf("take_action off: issues %+v, want the rejection recorded as not enforced", issues)
	}
	watch(true).runRescanCycle(ctx)
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("take_action on: the rejected skill was not quarantined (lstat err %v)", err)
	}
	if issues, _ := ReadAdmissionIssues(cfg.DataDir); len(issues) != 0 {
		t.Fatalf("take_action on: issues %+v after enforcement", issues)
	}
}

// GAP-0628: an administrator who reviewed a blocked skill and added an
// asset_policy allow rule for it saw it admitted while the agent still
// refused it as runtime-disabled. An allow rule releases the journal block
// and runtime disable, at the next admission or rescan, without a new copy.
func TestAllowRuleReleasesABlockedSkill(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cfg.Watch.RescanEnabled = true
	cfg.Watch.RescanContentGated = true
	path := filepath.Join(skillDir, "epa-high")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte("# epa-high\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "skill-scanner"} }
	w.runRescanCycle(context.Background()) // baseline: unchanged from now on
	for field, value := range map[string]string{"runtime": "disable", "install": "block"} {
		if err := store.SetActionFieldForConnector("skill", "epa-high", "claudecode", field, value, "auto-block: watch detected HIGH findings"); err != nil {
			t.Fatal(err)
		}
	}
	cfg.AssetPolicy.Skill.Allowed = []config.AssetPolicyRule{{Name: "epa-high"}}
	w.runRescanCycle(context.Background())
	entry, err := store.GetActionForConnector("skill", "epa-high", "claudecode")
	if err != nil {
		t.Fatal(err)
	}
	if entry != nil && (entry.Actions.Runtime != "" || entry.Actions.Install != "") {
		t.Fatalf("journal %+v, want the allow rule to clear the runtime disable and install block", entry.Actions)
	}
}
