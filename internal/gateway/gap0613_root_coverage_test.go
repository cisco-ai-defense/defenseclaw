// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

func TestGAP0613UnavailableRootDegradesWatcherHealthUntilRecovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership checks")
	}
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Guardrail.Connector = "claudecode"
	cfg.Gateway.Watcher.Enabled = true
	cfg.Gateway.Watcher.Skill.Enabled = true
	cfg.Gateway.Watcher.Plugin.Enabled = false
	cfg.Watch.DebounceMs = 50
	home := t.TempDir()
	target := filepath.Join(home, "dotfiles", "claude-dir")
	root := filepath.Join(home, ".claude", "skills")
	if err := os.MkdirAll(filepath.Join(target, "skills"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Dir(root)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	cfg.Gateway.Watcher.Skill.Dirs = []string{root}
	store, err := audit.NewStore(filepath.Join(cfg.DataDir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	s := &Sidecar{cfg: cfg, store: store, logger: audit.NewLogger(store), health: NewSidecarHealth()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.runWatcher(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("runWatcher: %v", err)
		}
	}()
	deadline := time.After(5 * time.Second)
	for {
		watcher := s.health.Snapshot().Watcher
		if watcher.State == StateDegraded && watcher.Details["watch_roots_unavailable"] == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("unavailable watcher health = %+v", watcher)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	deadline = time.After(5 * time.Second)
	for {
		watcher := s.health.Snapshot().Watcher
		if watcher.State == StateRunning && watcher.Details["watch_roots_unavailable"] == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("recovered watcher health = %+v", watcher)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestGAP0613UnavailableRootRuntimePolicyMatrix(t *testing.T) {
	store, logger := newNativeSkillRuntimeTestStore(t)
	root := filepath.Join(t.TempDir(), ".claude", "skills")
	issue := watcher.RootCoverageIssue{Kind: "skill", Path: root, Connector: "claudecode"}
	for _, tc := range []struct {
		name, tier, profile, sourcePath string
		managed, wantBlock              bool
	}{
		{"balanced", "default", "", filepath.Join(root, "ordinary"), false, false},
		{"permissive", "permissive", "", filepath.Join(root, "ordinary"), false, false},
		{"strict", "strict", "", filepath.Join(root, "ordinary"), false, true},
		{"strict-other-root", "strict", "", filepath.Join(t.TempDir(), "ordinary"), false, false},
		{"managed", "default", managed.ProfileStandalone, filepath.Join(root, "ordinary"), true, true},
		{"secure-client", "strict", managed.ProfileSecureClient, filepath.Join(root, "ordinary"), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.AssetPolicy = config.DefaultAssetPolicy()
			cfg.Guardrail.RulePack = tc.tier
			if tc.managed {
				cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
				cfg.Enterprise.Profile = tc.profile
			}
			api := &APIServer{store: store, logger: logger, scannerCfg: cfg,
				rootCoverage: func() []watcher.RootCoverageIssue { return []watcher.RootCoverageIssue{issue} }}
			decision, blocked := api.runtimeSkillAssetPolicyDecision(context.Background(), "claudecode", skillRuntimeProbe{
				Matched: true, SkillName: "ordinary", SourcePath: tc.sourcePath,
			})
			if blocked != tc.wantBlock || (blocked && (decision.Action != "block" || decision.Source != "watch-root-unavailable")) {
				t.Fatalf("blocked=%v decision=%+v, want blocked=%v", blocked, decision, tc.wantBlock)
			}
		})
	}
}
