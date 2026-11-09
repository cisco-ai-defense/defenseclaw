// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
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

func waitForRootCoverage(t *testing.T, w *InstallWatcher, what string, ok func([]RootCoverageIssue) bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for !ok(w.RootCoverageIssues()) {
		select {
		case <-deadline:
			t.Fatalf("%s: %+v", what, w.RootCoverageIssues())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// After chmod removes the write bit, the roots that exist resume with no
// restart (a path that is both a skill root and a plugin root is registered
// once). A root the agent has not created yet has no watch, so it stays
// reported, without the folder, until it is created and watched.
func TestLinkedRouteRepairEndsEveryCoverageIssueWithoutRestart(t *testing.T) {
	fixture := startLinkedRepairWatcher(t, 0o777)
	if err := os.Chmod(fixture.target, 0o700); err != nil {
		t.Fatal(err)
	}
	isAbsent := func(path string) bool {
		for _, absent := range fixture.absent {
			if path == absent || filepath.Dir(path) == absent {
				return true
			}
		}
		return false
	}
	waitForRootCoverage(t, fixture.w, "repaired route still names the folder or lost an unwatched root", func(issues []RootCoverageIssue) bool {
		if len(issues) != 2 {
			return false
		}
		for _, issue := range issues {
			if issue.Ancestor != "" || !strings.Contains(issue.Reason, "does not exist yet") {
				return false
			}
		}
		return true
	})
	for _, issue := range fixture.w.RootCoverageIssues() {
		if !isAbsent(issue.Path) {
			t.Errorf("a root that exists and is watched is still reported: %+v", issue)
		}
	}
	for _, absent := range fixture.absent {
		if _, err := os.Lstat(absent); !os.IsNotExist(err) {
			t.Errorf("the repair must not create %s: %v", absent, err)
		}
	}
	// The agent creates the roots: they are registered and the reports end.
	for _, issue := range fixture.w.RootCoverageIssues() {
		if err := os.MkdirAll(issue.Path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	waitForRootCoverage(t, fixture.w, "created roots still reported", func(issues []RootCoverageIssue) bool { return len(issues) == 0 })
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

// One absent path configured as both a skill root and a plugin root: once the
// path exists and is watched, the record of each kind ends, including the
// kind that reuses the watch the other kind registered.
func TestLinkedRouteRepairEndsSharedAbsentRootIssueOfEveryKind(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership checks")
	}
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cfg.Watch.RescanEnabled = false
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
		t.Skipf("symlinks unavailable: %v", err)
	}
	w := New(cfg, []string{root}, []string{root}, store, logger, nil, nil)
	w.SetRootConnectors(map[string]string{root: "claudecode"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	waitForRootCoverage(t, w, "writable route not recorded for both kinds", func(i []RootCoverageIssue) bool {
		return len(i) == 2 && i[0].Ancestor == target && i[1].Ancestor == target
	})
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	waitForRootCoverage(t, w, "repaired route before the root exists", func(i []RootCoverageIssue) bool {
		return len(i) == 2 && i[0].Ancestor == "" && i[1].Ancestor == ""
	})
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	waitForRootCoverage(t, w, "a kind kept its record after the shared root was watched", func(i []RootCoverageIssue) bool { return len(i) == 0 })
	time.Sleep(3 * w.debounce)
	if issues := w.RootCoverageIssues(); len(issues) != 0 {
		t.Fatalf("shared root still reported: %+v", issues)
	}
}

// startWatchedSharedRoot starts a watcher on one linked path that is both a
// skill root and a plugin root, and walks it to the state where the root is
// created and watched with no report outstanding.
func startWatchedSharedRoot(t *testing.T) (w *InstallWatcher, target, root string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership checks")
	}
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cfg.Watch.RescanEnabled = false
	home := t.TempDir()
	target = filepath.Join(home, "dotfiles", "claude-dir")
	root = filepath.Join(home, ".claude", "skills")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Dir(root)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	w = New(cfg, []string{root}, []string{root}, store, logger, nil, nil)
	w.SetRootConnectors(map[string]string{root: "claudecode"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(3 * w.debounce)
	waitForRootCoverage(t, w, "a safe shared root is reported", func(i []RootCoverageIssue) bool { return len(i) == 0 })
	return w, target, root
}

func rootKinds(issues []RootCoverageIssue) string {
	kinds := make([]string, 0, len(issues))
	for _, issue := range issues {
		kinds = append(kinds, issue.Kind)
	}
	slices.Sort(kinds)
	return strings.Join(kinds, ",")
}

// A watched shared root whose link route becomes writable again is
// unavailable for both kinds (the plugin kind shares the skill kind watch),
// and both records end when the route is repaired.
func TestSharedRootMadeWritableAgainIsUnavailableForEveryKind(t *testing.T) {
	w, target, _ := startWatchedSharedRoot(t)
	if err := os.Chmod(target, 0o777); err != nil {
		t.Fatal(err)
	}
	waitForRootCoverage(t, w, "a kind of the shared root is not reported after its route became writable", func(i []RootCoverageIssue) bool {
		return rootKinds(i) == "plugin,skill" && i[0].Ancestor == target && i[1].Ancestor == target
	})
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	waitForRootCoverage(t, w, "a kind of the repaired shared root is still reported", func(i []RootCoverageIssue) bool { return len(i) == 0 })
}

// A watched shared root that is moved away is unavailable for both kinds
// until the root made again at its path is watched and admitted, also when
// that happens while the route is writable.
func TestReplacedSharedRootIsUnavailableForEveryKindUntilWatched(t *testing.T) {
	w, target, root := startWatchedSharedRoot(t)
	if err := os.Chmod(target, 0o777); err != nil {
		t.Fatal(err)
	}
	waitForRootCoverage(t, w, "writable route not reported for both kinds", func(i []RootCoverageIssue) bool {
		return rootKinds(i) == "plugin,skill"
	})
	if err := os.Rename(root, root+"-away"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "ordinary"), 0o700); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * w.debounce)
	if kinds := rootKinds(w.RootCoverageIssues()); kinds != "plugin,skill" {
		t.Fatalf("a replaced root on a writable route must stay unavailable for both kinds, got %q", kinds)
	}
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	waitForRootCoverage(t, w, "a kind of the replaced and repaired shared root is still reported", func(i []RootCoverageIssue) bool { return len(i) == 0 })

	// With a safe route, moving the root away alone reports both kinds.
	if err := os.Rename(root, root+"-gone"); err != nil {
		t.Fatal(err)
	}
	waitForRootCoverage(t, w, "a removed shared root is not reported for both kinds", func(i []RootCoverageIssue) bool { return rootKinds(i) == "plugin,skill" })
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	waitForRootCoverage(t, w, "a kind of the made-again shared root is still reported", func(i []RootCoverageIssue) bool { return len(i) == 0 })
}
