// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// sharedRootInvalidationFixture is a linked path that is both a skill root and
// a plugin root, created and watched under strict policy, so the tests can
// invalidate the one watch the two kinds share.
type sharedRootInvalidationFixture struct {
	w      *watcher.InstallWatcher
	api    *APIServer
	cfg    *config.Config
	target string
	root   string
}

func startWatchedSharedRootUnderStrict(t *testing.T) *sharedRootInvalidationFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix linked-route ownership")
	}
	home := t.TempDir()
	target := filepath.Join(home, "dotfiles", "claude-dir")
	root := filepath.Join(home, ".claude", "skills")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Dir(root)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePack = "strict"
	cfg.AssetPolicy = config.DefaultAssetPolicy()
	cfg.Watch.DebounceMs = 100
	cfg.Watch.RescanEnabled = false
	store, logger := newNativeSkillRuntimeTestStore(t)
	w := watcher.New(cfg, []string{root}, []string{root}, store, logger, nil, nil)
	w.SetRootConnectors(map[string]string{root: "claudecode"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(3 * time.Duration(cfg.Watch.DebounceMs) * time.Millisecond)
	return &sharedRootInvalidationFixture{
		w:      w,
		api:    &APIServer{store: store, logger: logger, scannerCfg: cfg, rootCoverage: w.RootCoverageIssues},
		cfg:    cfg,
		target: target,
		root:   root,
	}
}

func (f *sharedRootInvalidationFixture) wait(t *testing.T, what string, ok func([]watcher.RootCoverageIssue) bool) {
	t.Helper()
	deadline := time.After(15 * time.Second)
	for !ok(f.w.RootCoverageIssues()) {
		select {
		case <-deadline:
			t.Fatalf("%s: %+v", what, f.w.RootCoverageIssues())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (f *sharedRootInvalidationFixture) pluginHeld(name string) (held bool, source string) {
	path := filepath.Join(f.root, name)
	_, blocked := f.api.unavailableRootDecision(f.cfg, "plugin", "claudecode", "hook", name, []string{path})
	runtimeDecision, runtimeBlocked := f.api.runtimeSkillAssetPolicyDecision(context.Background(), "claudecode", skillRuntimeProbe{
		Matched: true, TargetType: "plugin", SkillName: name, SourcePath: path,
	})
	return blocked && runtimeBlocked, runtimeDecision.Source
}

func (f *sharedRootInvalidationFixture) bothKindsReported(i []watcher.RootCoverageIssue) bool {
	return len(i) == 2 && i[0].Kind != i[1].Kind
}

// The watched shared root is made writable again. The skill kind and the
// plugin kind share the watch, so strict admission holds a plugin under it
// until the route is repaired, and allows it again after.
func TestStrictHoldsPluginUnderSharedRootMadeWritableAgain(t *testing.T) {
	f := startWatchedSharedRootUnderStrict(t)
	if err := os.Chmod(f.target, 0o777); err != nil {
		t.Fatal(err)
	}
	f.wait(t, "the writable route was not reported for both kinds", f.bothKindsReported)
	if err := os.MkdirAll(filepath.Join(f.root, "ordinary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if held, source := f.pluginHeld("ordinary"); !held {
		t.Fatalf("plugin under a shared root on a writable route was not held: source=%q issues=%+v", source, f.w.RootCoverageIssues())
	}
	if err := os.Chmod(f.target, 0o700); err != nil {
		t.Fatal(err)
	}
	f.wait(t, "the repaired shared root is still reported", func(i []watcher.RootCoverageIssue) bool { return len(i) == 0 })
	if held, source := f.pluginHeld("ordinary"); held {
		t.Fatalf("benign plugin held after the route was repaired: source=%q issues=%+v", source, f.w.RootCoverageIssues())
	}
}

// The watched shared root is moved away and a replacement is made at its
// path. Strict admission holds a plugin in the replacement until the
// replacement is watched and admitted.
func TestStrictHoldsPluginUnderReplacedSharedRootUntilWatched(t *testing.T) {
	f := startWatchedSharedRootUnderStrict(t)
	if err := os.Chmod(f.target, 0o777); err != nil {
		t.Fatal(err)
	}
	f.wait(t, "the writable route was not reported for both kinds", f.bothKindsReported)
	if err := os.Rename(f.root, f.root+"-away"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.root, "ordinary"), 0o700); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Duration(f.cfg.Watch.DebounceMs) * time.Millisecond)
	if held, source := f.pluginHeld("ordinary"); !held {
		t.Fatalf("plugin in a replaced shared root on a writable route was not held: source=%q issues=%+v", source, f.w.RootCoverageIssues())
	}
	if err := os.Chmod(f.target, 0o700); err != nil {
		t.Fatal(err)
	}
	f.wait(t, "the replaced and repaired shared root is still reported", func(i []watcher.RootCoverageIssue) bool { return len(i) == 0 })
	if held, source := f.pluginHeld("ordinary"); held {
		t.Fatalf("benign plugin held once the replacement was watched: source=%q issues=%+v", source, f.w.RootCoverageIssues())
	}
}
