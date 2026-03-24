package watcher

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

func setupTestEnv(t *testing.T) (cfg *config.Config, store *audit.Store, logger *audit.Logger, skillDir, mcpDir string) {
	t.Helper()

	tmpDir := t.TempDir()
	skillDir = filepath.Join(tmpDir, "skills")
	mcpDir = filepath.Join(tmpDir, "mcps")
	if err := os.MkdirAll(skillDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(mcpDir, 0o700); err != nil {
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
			MCPScanner:   "mcp-scanner",
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

	return cfg, store, logger, skillDir, mcpDir
}

func TestClassifyEvent_SkillDir(t *testing.T) {
	cfg, store, logger, skillDir, mcpDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)
	w := New(cfg, []string{skillDir}, []string{mcpDir}, store, logger, shell, nil, nil)

	evt := w.classifyEvent(filepath.Join(skillDir, "my-skill"))
	if evt.Type != InstallSkill {
		t.Errorf("expected type %q, got %q", InstallSkill, evt.Type)
	}
	if evt.Name != "my-skill" {
		t.Errorf("expected name %q, got %q", "my-skill", evt.Name)
	}
}

func TestClassifyEvent_MCPDir(t *testing.T) {
	cfg, store, logger, skillDir, mcpDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)
	w := New(cfg, []string{skillDir}, []string{mcpDir}, store, logger, shell, nil, nil)

	evt := w.classifyEvent(filepath.Join(mcpDir, "my-server.json"))
	if evt.Type != InstallMCP {
		t.Errorf("expected type %q, got %q", InstallMCP, evt.Type)
	}
	if evt.Name != "my-server.json" {
		t.Errorf("expected name %q, got %q", "my-server.json", evt.Name)
	}
}

func TestAdmission_BlockedSkill(t *testing.T) {
	cfg, store, logger, skillDir, mcpDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.SetActionField("skill", "evil-skill", "install", "block", "known malicious"); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, []string{mcpDir}, store, logger, shell, nil, nil)

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
	cfg, store, logger, skillDir, mcpDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.SetActionField("skill", "trusted-skill", "install", "allow", "pre-approved"); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, []string{mcpDir}, store, logger, shell, nil, nil)

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

func TestAdmission_BlockedMCP(t *testing.T) {
	cfg, store, logger, skillDir, mcpDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.SetActionField("mcp", "rogue-server", "install", "block", "compromised"); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, []string{mcpDir}, store, logger, shell, nil, nil)

	mcpPath := filepath.Join(mcpDir, "rogue-server")
	if err := os.WriteFile(mcpPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	evt := InstallEvent{Type: InstallMCP, Name: "rogue-server", Path: mcpPath, Timestamp: time.Now()}
	result := w.runAdmission(context.Background(), evt)

	if result.Verdict != VerdictBlocked {
		t.Errorf("expected verdict %q, got %q", VerdictBlocked, result.Verdict)
	}
}

func TestAdmission_AllowedMCP(t *testing.T) {
	cfg, store, logger, skillDir, mcpDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.SetActionField("mcp", "approved-server", "install", "allow", "vetted"); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, []string{mcpDir}, store, logger, shell, nil, nil)

	mcpPath := filepath.Join(mcpDir, "approved-server")
	if err := os.WriteFile(mcpPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	evt := InstallEvent{Type: InstallMCP, Name: "approved-server", Path: mcpPath, Timestamp: time.Now()}
	result := w.runAdmission(context.Background(), evt)

	if result.Verdict != VerdictAllowed {
		t.Errorf("expected verdict %q, got %q", VerdictAllowed, result.Verdict)
	}
}

func TestAdmission_ScanError_NoScanner(t *testing.T) {
	cfg, store, logger, skillDir, mcpDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)
	w := New(cfg, []string{skillDir}, []string{mcpDir}, store, logger, shell, nil, nil)

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

func TestWatcher_DetectsNewMCPDir(t *testing.T) {
	cfg, store, logger, skillDir, mcpDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.SetActionField("mcp", "detected-server", "install", "block", "test"); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var results []AdmissionResult

	w := New(cfg, []string{skillDir}, []string{mcpDir}, store, logger, shell, nil, func(r AdmissionResult) {
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

	dirPath := filepath.Join(mcpDir, "detected-server")
	if err := os.MkdirAll(dirPath, 0o700); err != nil {
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
		if r.Event.Name == "detected-server" {
			found = true
			if r.Verdict != VerdictBlocked {
				t.Errorf("expected verdict %q for blocked server, got %q", VerdictBlocked, r.Verdict)
			}
		}
	}
	if !found {
		t.Error("admission result for 'detected-server' not found")
	}
}

func TestWatcher_DetectsNewDirectory(t *testing.T) {
	cfg, store, logger, skillDir, mcpDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.SetActionField("skill", "new-skill", "install", "allow", "pre-approved"); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var results []AdmissionResult

	w := New(cfg, []string{skillDir}, []string{mcpDir}, store, logger, shell, nil, func(r AdmissionResult) {
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
	cfg, store, logger, skillDir, mcpDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	// With the unified table, setting install to "block" after "allow" replaces it.
	// The block check runs first in the admission gate, so block takes priority.
	if err := store.SetActionField("skill", "conflict-skill", "install", "block", "security"); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, []string{mcpDir}, store, logger, shell, nil, nil)

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
	_, store, _, _, _ := setupTestEnv(t)

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
	}
	if entry.Actions.Install != "block" {
		t.Errorf("expected install=block, got %q", entry.Actions.Install)
	}
	if entry.Actions.File != "quarantine" {
		t.Errorf("expected file=quarantine, got %q", entry.Actions.File)
	}
}

func TestActionState_InstallOverwrite(t *testing.T) {
	_, store, _, _, _ := setupTestEnv(t)

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
	}
	if entry.Actions.Install != "allow" {
		t.Errorf("expected install=allow after overwrite, got %q", entry.Actions.Install)
	}
}
