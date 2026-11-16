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

// A plugin cache configured under a skill root gets its watch from the skill
// root content watches, not from the plugin root. The configured plugin root
// still needs its own unsafe-route record: strict admission holds a plugin
// under it while the linked route is writable, and allows it again once the
// route is repaired.
func TestStrictHoldsPluginInCacheNestedUnderSkillRootWhileRouteWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix linked-route ownership")
	}
	home := t.TempDir()
	target := filepath.Join(home, "dotfiles", "claude-dir")
	skills := filepath.Join(home, ".claude", "skills")
	plugins := filepath.Join(skills, "cache")
	ordinary := filepath.Join(plugins, "marketplace", "ordinary", "v1")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Dir(skills)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.MkdirAll(ordinary, 0o700); err != nil {
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
	w := watcher.New(cfg, []string{skills}, []string{plugins}, store, logger, nil, nil)
	w.SetRootConnectors(map[string]string{skills: "claudecode", plugins: "claudecode"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(4 * time.Duration(cfg.Watch.DebounceMs) * time.Millisecond)
	api := &APIServer{store: store, logger: logger, scannerCfg: cfg, rootCoverage: w.RootCoverageIssues}
	pluginHeld := func() (bool, string) {
		decision, blocked := api.runtimeSkillAssetPolicyDecision(context.Background(), "claudecode", skillRuntimeProbe{
			Matched: true, TargetType: "plugin", SkillName: "ordinary", SourcePath: ordinary,
		})
		return blocked, decision.Source
	}
	wait := func(what string, ok func([]watcher.RootCoverageIssue) bool) {
		t.Helper()
		deadline := time.After(15 * time.Second)
		for !ok(w.RootCoverageIssues()) {
			select {
			case <-deadline:
				t.Fatalf("%s: %+v", what, w.RootCoverageIssues())
			case <-time.After(10 * time.Millisecond):
			}
		}
	}

	if issues := w.RootCoverageIssues(); len(issues) != 0 {
		t.Fatalf("safe roots reported before the route changed: %+v", issues)
	}
	if held, source := pluginHeld(); held {
		t.Fatalf("benign plugin held on a safe route: source=%q", source)
	}
	if err := os.Chmod(target, 0o777); err != nil {
		t.Fatal(err)
	}
	wait("the writable route was not reported for both kinds", func(i []watcher.RootCoverageIssue) bool {
		return len(i) == 2 && i[0].Kind != i[1].Kind
	})
	if held, source := pluginHeld(); !held || source != "watch-root-unavailable" {
		t.Fatalf("plugin in a cache nested under a writable skill root was not held: held=%v source=%q issues=%+v", held, source, w.RootCoverageIssues())
	}
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	wait("the repaired roots are still reported", func(i []watcher.RootCoverageIssue) bool { return len(i) == 0 })
	if held, source := pluginHeld(); held {
		t.Fatalf("benign plugin held after the route was repaired: source=%q issues=%+v", source, w.RootCoverageIssues())
	}
}
