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
	"github.com/defenseclaw/defenseclaw/internal/skillrootsafe"
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

func TestGAP0613StrictUnavailableRootRequiresProvenOutsidePath(t *testing.T) {
	store, logger := newNativeSkillRuntimeTestStore(t)
	root := filepath.Join(t.TempDir(), ".claude", "skills")
	for _, tc := range []struct {
		name, tier, source string
		blocked            bool
	}{
		{"strict-root-itself", "strict", root, true},
		{"strict-clean-inside", "strict", filepath.Join(root, "ordinary"), true},
		{"strict-parent-inside", "strict", root + string(filepath.Separator) + ".." + string(filepath.Separator) + "skills" + string(filepath.Separator) + "ordinary", true},
		{"strict-relative-unknown", "strict", filepath.Join("skills", "ordinary"), true},
		{"strict-proven-outside", "strict", filepath.Join(t.TempDir(), "ordinary"), false},
		{"balanced-relative", "default", filepath.Join("skills", "ordinary"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.AssetPolicy = config.DefaultAssetPolicy()
			cfg.Guardrail.RulePack = tc.tier
			api := &APIServer{store: store, logger: logger, scannerCfg: cfg,
				rootCoverage: func() []watcher.RootCoverageIssue {
					return []watcher.RootCoverageIssue{{Kind: "skill", Path: root, Connector: "claudecode"}}
				}}
			decision, blocked := api.runtimeSkillAssetPolicyDecision(context.Background(), "claudecode", skillRuntimeProbe{
				Matched: true, SkillName: "ordinary", SourcePath: tc.source,
			})
			if blocked != tc.blocked || blocked && decision.Action != "block" {
				t.Fatalf("source=%q blocked=%v decision=%+v, want blocked=%v", tc.source, blocked, decision, tc.blocked)
			}
		})
	}
}

func TestGAP0613UnavailableRootAliasesStayCovered(t *testing.T) {
	home := t.TempDir()
	physicalRoot := filepath.Join(home, "shared", "skills")
	linkedRoot := filepath.Join(home, ".claude", "skills")
	linkedParent := filepath.Join(home, "linked-agent")
	linkedParentRoot := filepath.Join(linkedParent, "skills")
	rootAlias := filepath.Join(home, "other", "skills")
	parentAlias := filepath.Join(home, "shared-alias")
	for _, dir := range []string{
		filepath.Join(physicalRoot, "ordinary"), filepath.Dir(linkedRoot), filepath.Dir(rootAlias),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Dir(physicalRoot), 0o777); err != nil {
		t.Fatal(err)
	}
	for _, link := range []struct{ name, target string }{
		{linkedRoot, physicalRoot},
		{linkedParent, filepath.Dir(physicalRoot)},
		{rootAlias, physicalRoot},
		{parentAlias, filepath.Dir(physicalRoot)},
	} {
		if err := os.Symlink(link.target, link.name); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	if runtime.GOOS != "windows" {
		if _, err := skillrootsafe.Resolve(linkedRoot, nil); err == nil {
			t.Fatal("unavailable linked root was accepted")
		}
	}
	missingAlias := filepath.Join(home, "missing-alias")
	if err := os.Symlink(filepath.Join(physicalRoot, "pending"), missingAlias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	store, logger := newNativeSkillRuntimeTestStore(t)
	for _, root := range []string{linkedRoot, linkedParentRoot} {
		t.Run(filepath.Base(filepath.Dir(root)), func(t *testing.T) {
			for _, tier := range []string{"strict", "managed", "default", "permissive"} {
				t.Run(tier, func(t *testing.T) {
					cfg := config.DefaultConfig()
					cfg.AssetPolicy = config.DefaultAssetPolicy()
					cfg.Guardrail.RulePack = tier
					if tier == "managed" {
						cfg.Guardrail.RulePack = "default"
						cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
						cfg.Enterprise.Profile = managed.ProfileStandalone
					}
					api := &APIServer{store: store, logger: logger, scannerCfg: cfg,
						rootCoverage: func() []watcher.RootCoverageIssue {
							return []watcher.RootCoverageIssue{{Kind: "skill", Path: root, Connector: "claudecode"}}
						}}
					for _, source := range []struct {
						name, path string
						underRoot  bool
					}{
						{"physical", filepath.Join(physicalRoot, "ordinary"), true},
						{"root-alias", filepath.Join(rootAlias, "ordinary"), true},
						{"parent-alias", filepath.Join(parentAlias, "skills", "ordinary"), true},
						{"unresolved-alias", filepath.Join(missingAlias, "ordinary"), true},
						{"outside", filepath.Join(home, "outside", "ordinary"), false},
					} {
						t.Run(source.name, func(t *testing.T) {
							name, path, _ := skillFromMap(map[string]interface{}{"skill_name": "ordinary", "skill_path": source.path})
							if name != "ordinary" || path != source.path {
								t.Fatalf("hook source changed: %q %q", name, path)
							}
							decision, blocked := api.runtimeSkillAssetPolicyDecision(context.Background(), "claudecode", skillRuntimeProbe{
								Matched: true, SkillName: name, SourcePath: path,
							})
							wantBlock := (tier == "strict" || tier == "managed") && source.underRoot
							if blocked != wantBlock || wantBlock && (decision.Action != "block" || decision.Source != "watch-root-unavailable") {
								t.Fatalf("source=%q blocked=%v decision=%+v, want blocked=%v", path, blocked, decision, wantBlock)
							}
						})
					}
				})
			}
		})
	}
}
