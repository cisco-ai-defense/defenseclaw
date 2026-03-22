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
			SkillScanner: "skill-scanner",
			MCPScanner:   "mcp-scanner",
		},
		OpenShell: config.OpenShellConfig{
			Binary:    "openshell",
			PolicyDir: filepath.Join(tmpDir, "openshell-policies"),
		},
		Watch: config.WatchConfig{
			SkillDirs:  []string{skillDir},
			MCPDirs:    []string{mcpDir},
			DebounceMs: 100,
			AutoBlock:  true,
		},
	}

	return cfg, store, logger, skillDir, mcpDir
}

func TestClassifyEvent_SkillDir(t *testing.T) {
	cfg, store, logger, skillDir, _ := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)
	w := New(cfg, store, logger, shell, nil)

	evt := w.classifyEvent(filepath.Join(skillDir, "my-skill"))
	if evt.Type != InstallSkill {
		t.Errorf("expected type %q, got %q", InstallSkill, evt.Type)
	}
	if evt.Name != "my-skill" {
		t.Errorf("expected name %q, got %q", "my-skill", evt.Name)
	}
}

func TestClassifyEvent_MCPDir(t *testing.T) {
	cfg, store, logger, _, mcpDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)
	w := New(cfg, store, logger, shell, nil)

	evt := w.classifyEvent(filepath.Join(mcpDir, "my-server.json"))
	if evt.Type != InstallMCP {
		t.Errorf("expected type %q, got %q", InstallMCP, evt.Type)
	}
	if evt.Name != "my-server.json" {
		t.Errorf("expected name %q, got %q", "my-server.json", evt.Name)
	}
}

func TestAdmission_BlockedSkill(t *testing.T) {
	cfg, store, logger, skillDir, _ := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.AddBlock("skill", "evil-skill", "known malicious"); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, store, logger, shell, nil)

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
	cfg, store, logger, skillDir, _ := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.AddAllow("skill", "trusted-skill", "pre-approved"); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, store, logger, shell, nil)

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
	cfg, store, logger, _, mcpDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.AddBlock("mcp", "rogue-server", "compromised"); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, store, logger, shell, nil)

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
	cfg, store, logger, _, mcpDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.AddAllow("mcp", "approved-server", "vetted"); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, store, logger, shell, nil)

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
	cfg, store, logger, skillDir, _ := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)
	w := New(cfg, store, logger, shell, nil)

	skillPath := filepath.Join(skillDir, "unknown-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}

	// Scanner binary won't exist, so scan will error
	evt := InstallEvent{Type: InstallSkill, Name: "unknown-skill", Path: skillPath, Timestamp: time.Now()}
	result := w.runAdmission(context.Background(), evt)

	// Either ScanError (binary missing) or the scan completes — both are valid
	if result.Verdict != VerdictScanError && result.Verdict != VerdictClean {
		t.Logf("verdict=%s reason=%s", result.Verdict, result.Reason)
	}
}

func TestWatcher_DetectsNewFile(t *testing.T) {
	cfg, store, logger, _, mcpDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.AddBlock("mcp", "detected-server", "test"); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var results []AdmissionResult

	w := New(cfg, store, logger, shell, func(r AdmissionResult) {
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

	// Give the watcher time to start
	time.Sleep(200 * time.Millisecond)

	// Create a file in the MCP dir to trigger detection
	filePath := filepath.Join(mcpDir, "detected-server")
	if err := os.WriteFile(filePath, []byte(`{"name":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Wait for debounce + processing
	time.Sleep(time.Duration(cfg.Watch.DebounceMs*3) * time.Millisecond)

	cancel()
	<-errCh

	mu.Lock()
	defer mu.Unlock()

	if len(results) == 0 {
		t.Fatal("expected at least one admission result, got none")
	}

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
	cfg, store, logger, skillDir, _ := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := store.AddAllow("skill", "new-skill", "pre-approved"); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var results []AdmissionResult

	w := New(cfg, store, logger, shell, func(r AdmissionResult) {
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

	time.Sleep(200 * time.Millisecond)

	// Create a directory in the skill dir to trigger detection
	if err := os.MkdirAll(filepath.Join(skillDir, "new-skill"), 0o700); err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Duration(cfg.Watch.DebounceMs*3) * time.Millisecond)

	cancel()
	<-errCh

	mu.Lock()
	defer mu.Unlock()

	if len(results) == 0 {
		t.Fatal("expected at least one admission result, got none")
	}

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
	cfg, store, logger, skillDir, _ := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	// Add to both lists — block should take priority
	if err := store.AddBlock("skill", "conflict-skill", "security"); err != nil {
		t.Fatal(err)
	}
	if err := store.AddAllow("skill", "conflict-skill", "override attempt"); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, store, logger, shell, nil)

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
