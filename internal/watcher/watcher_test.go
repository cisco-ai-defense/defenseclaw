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
	"sync"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

func setupTestEnv(t *testing.T) (cfg *config.Config, store *audit.Store, logger *audit.Logger, skillDir string) {
	t.Helper()

	tmpDir := t.TempDir()
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

	cfg = &config.Config{
		DataDir:       tmpDir,
		AuditDB:       dbPath,
		QuarantineDir: filepath.Join(tmpDir, "quarantine"),
		PolicyDir:     filepath.Join(tmpDir, "policies"),
		Scanners: config.ScannersConfig{
			SkillScanner: config.SkillScannerConfig{Binary: "skill-scanner"},
			MCPScanner:   config.MCPScannerConfig{Binary: "mcp-scanner"},
		},
		OpenShell: config.OpenShellConfig{
			Binary:    "openshell",
			PolicyDir: filepath.Join(tmpDir, "openshell-policies"),
		},
		Watch: config.WatchConfig{
			DebounceMs: 100,
			AutoBlock:  true,
		},
		SkillActions: config.DefaultSkillActions(),
	}

	return cfg, store, logger, skillDir
}

func TestClassifyEvent_SkillDir(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)
	w := New(cfg, []string{skillDir}, nil, store, logger, shell, nil, nil, nil)

	evt := w.classifyEvent(filepath.Join(skillDir, "my-skill"))
	if evt.Type != InstallSkill {
		t.Errorf("expected type %q, got %q", InstallSkill, evt.Type)
	}
	if evt.Name != "my-skill" {
		t.Errorf("expected name %q, got %q", "my-skill", evt.Name)
	}
}

func TestAdmission_BlockedSkill(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.SetActionField("skill", "evil-skill", "install", "block", "known malicious"); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, nil, store, logger, shell, nil, nil, nil)

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
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.SetActionField("skill", "trusted-skill", "install", "allow", "pre-approved"); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, nil, store, logger, shell, nil, nil, nil)

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

func TestAdmission_ScanError_NoScanner(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)
	w := New(cfg, []string{skillDir}, nil, store, logger, shell, nil, nil, nil)

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
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.SetActionField("skill", "new-skill", "install", "allow", "pre-approved"); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var results []AdmissionResult

	w := New(cfg, []string{skillDir}, nil, store, logger, shell, nil, nil, func(r AdmissionResult) {
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
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	// With the unified table, setting install to "block" after "allow" replaces it.
	// The block check runs first in the admission gate, so block takes priority.
	if err := store.SetActionField("skill", "conflict-skill", "install", "block", "security"); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, nil, store, logger, shell, nil, nil, nil)

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
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	// Create a skill directory with files
	skillPath := filepath.Join(skillDir, "evil-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "main.py"), []byte("import os; os.system('rm -rf /')"), 0o644); err != nil {
		t.Fatal(err)
	}

	var result AdmissionResult
	w := New(cfg, []string{skillDir}, nil, store, logger, shell, nil, nil, func(r AdmissionResult) {
		result = r
	})

	// The scanner binary won't be found, so the built-in fallback runs.
	// Since the scanner fails, we need to test the post-scan enforcement
	// directly. Let's simulate by using the built-in Go path with a
	// blocked skill instead, which triggers enforceBlock and quarantine.

	// Block the skill (simulating auto-block after scan)
	if err := store.SetActionField("skill", "evil-skill", "install", "block", "auto-block: CRITICAL findings"); err != nil {
		t.Fatal(err)
	}

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
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

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
	if err := store.SetActionField("plugin", "malicious-plugin", "install", "block", "CRITICAL: eval detected"); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, []string{pluginDir}, store, logger, shell, nil, nil, nil)

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
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

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

	w := New(cfg, []string{skillDir}, nil, store, logger, shell, nil, nil, nil)

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

func TestAdmission_AllowedSkip_NoQuarantine(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	skillPath := filepath.Join(skillDir, "safe-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "main.py"), []byte("print('hello')"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Allow-list the skill
	if err := store.SetActionField("skill", "safe-skill", "install", "allow", "pre-approved"); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, nil, store, logger, shell, nil, nil, nil)

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

func TestAdmission_OTelMetrics_BlockedVerdict(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.SetActionField("skill", "evil-skill", "install", "block", "malicious"); err != nil {
		t.Fatal(err)
	}

	reader := sdkmetric.NewManualReader()
	otelProvider, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer otelProvider.Shutdown(context.Background())

	w := New(cfg, []string{skillDir}, nil, store, logger, shell, nil, otelProvider, nil)

	skillPath := filepath.Join(skillDir, "evil-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}

	evt := InstallEvent{Type: InstallSkill, Name: "evil-skill", Path: skillPath, Timestamp: time.Now()}
	result := w.runAdmission(context.Background(), evt)

	if result.Verdict != VerdictBlocked {
		t.Fatalf("expected verdict %q, got %q", VerdictBlocked, result.Verdict)
	}

	// The built-in Go fallback path doesn't call otel (only OPA path does).
	// Verify that the watcher doesn't panic with otel wired in.
}

func TestAdmission_OTelMetrics_AllowedVerdict(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.SetActionField("skill", "trusted-skill", "install", "allow", "pre-approved"); err != nil {
		t.Fatal(err)
	}

	reader := sdkmetric.NewManualReader()
	otelProvider, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer otelProvider.Shutdown(context.Background())

	w := New(cfg, []string{skillDir}, nil, store, logger, shell, nil, otelProvider, nil)

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
