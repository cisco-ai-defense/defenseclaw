// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// linkedRepairFixture is a linked agent folder (home/.claude -> home/dotfiles/
// claude-dir) holding a skills folder, watched as a skill root and as a plugin
// root, plus a commands root and a plugin cache root the agent has not created.
type linkedRepairFixture struct {
	w      *InstallWatcher
	target string
	absent []string
}

func startLinkedRepairWatcher(t *testing.T, mode os.FileMode) *linkedRepairFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership checks")
	}
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	home := t.TempDir()
	target := filepath.Join(home, "dotfiles", "claude-dir")
	skills := filepath.Join(home, ".claude", "skills")
	commands := filepath.Join(home, ".claude", "commands")
	cache := filepath.Join(home, ".claude", "plugins", "cache")
	if err := os.MkdirAll(filepath.Join(target, "skills"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Dir(skills)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	w := New(cfg, []string{skills, commands}, []string{skills, cache}, store, logger, nil, nil)
	w.SetRootConnectors(map[string]string{skills: "claudecode", commands: "claudecode", cache: "claudecode"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	fixture := &linkedRepairFixture{w: w, target: target, absent: []string{commands, filepath.Dir(cache)}}
	deadline := time.After(5 * time.Second)
	for len(w.RootCoverageIssues()) < 4 {
		select {
		case <-deadline:
			t.Fatal("a writable linked route did not report all four roots")
		case <-time.After(20 * time.Millisecond):
		}
	}
	return fixture
}

// After chmod removes the write bit, every root the folder made unavailable
// resumes with no restart: the roots the agent has not created yet, and a path
// that is both a skill root and a plugin root, which the watcher registers
// once.
func TestLinkedRouteRepairEndsEveryCoverageIssueWithoutRestart(t *testing.T) {
	fixture := startLinkedRepairWatcher(t, 0o777)
	if err := os.Chmod(fixture.target, 0o700); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	for len(fixture.w.RootCoverageIssues()) != 0 {
		select {
		case <-deadline:
			t.Fatalf("repaired route still reported: %+v", fixture.w.RootCoverageIssues())
		case <-time.After(20 * time.Millisecond):
		}
	}
	for _, absent := range fixture.absent {
		if _, err := os.Lstat(absent); !os.IsNotExist(err) {
			t.Errorf("the repair must not create %s: %v", absent, err)
		}
	}
}

// A route that is still writable keeps every root reported and the folder named.
func TestLinkedRouteStillWritableKeepsCoverageIssues(t *testing.T) {
	fixture := startLinkedRepairWatcher(t, 0o777)
	time.Sleep(2 * time.Second)
	issues := fixture.w.RootCoverageIssues()
	if len(issues) < 3 {
		t.Fatalf("a still-writable route must keep its roots reported: %+v", issues)
	}
	for _, issue := range issues {
		if issue.Ancestor != fixture.target {
			t.Errorf("issue %s %s names %q, want %q", issue.Kind, issue.Path, issue.Ancestor, fixture.target)
		}
	}
}
