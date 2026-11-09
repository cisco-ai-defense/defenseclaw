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

// A linked route that was writable is repaired while its skills folder does
// not exist yet. The folder has no watch, so strict admission keeps holding a
// skill that appears there until the watcher has registered the folder.
func TestStrictHoldsUnwatchedSkillRootAfterLinkedRouteRepair(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix linked-route ownership")
	}
	home := t.TempDir()
	target := filepath.Join(home, "dotfiles", "claude-dir")
	root := filepath.Join(home, ".claude", "skills")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Dir(root)); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePack = "strict"
	cfg.AssetPolicy = config.DefaultAssetPolicy()
	cfg.Watch.DebounceMs = 5000
	cfg.Watch.RescanEnabled = false
	store, logger := newNativeSkillRuntimeTestStore(t)
	w := watcher.New(cfg, []string{root}, nil, store, logger, nil, nil)
	w.SetRootConnectors(map[string]string{root: "claudecode"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitIssues := func(what string, ok func([]watcher.RootCoverageIssue) bool) {
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
	waitIssues("writable route not recorded", func(i []watcher.RootCoverageIssue) bool {
		return len(i) == 1 && i[0].Ancestor != ""
	})
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	// The record stops naming the folder but stays: the root is not watched.
	waitIssues("repaired route should still report the unwatched root without the folder", func(i []watcher.RootCoverageIssue) bool {
		return len(i) == 1 && i[0].Ancestor == ""
	})
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("the unwatched root unexpectedly exists: %v", err)
	}
	skill := filepath.Join(root, "ordinary")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: ordinary\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{store: store, logger: logger, scannerCfg: cfg, rootCoverage: w.RootCoverageIssues}
	decision, blocked := api.runtimeSkillAssetPolicyDecision(context.Background(), "claudecode", skillRuntimeProbe{
		Matched: true, SkillName: "ordinary", SourcePath: skill,
	})
	if !blocked || decision.Source != "watch-root-unavailable" {
		t.Fatalf("new unscanned skill was not held: blocked=%v source=%q issues=%+v", blocked, decision.Source, w.RootCoverageIssues())
	}
}
