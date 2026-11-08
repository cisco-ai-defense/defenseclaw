//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func stubRootRouteWarnings(t *testing.T, folders []string) {
	t.Helper()
	old := rootRouteWarnings
	rootRouteWarnings = func(path string, _ func(string) (string, error)) (string, []string, error) {
		return path, folders, nil
	}
	t.Cleanup(func() { rootRouteWarnings = old })
}

func newWarnedWatcher(t *testing.T, folders []string) (*InstallWatcher, string, chan []RootWarning) {
	t.Helper()
	cfg, store, logger, root := setupTestEnv(t)
	cfg.Watch.RescanEnabled = false
	stubRootRouteWarnings(t, folders)
	warnings := make(chan []RootWarning, 8)
	w := New(cfg, []string{root}, nil, store, logger, nil, nil)
	w.SetRootWarningHandler(func(current []RootWarning) { warnings <- current })
	return w, root, warnings
}

func runWarnedWatcher(t *testing.T, folders []string) (*InstallWatcher, string, chan []RootWarning) {
	t.Helper()
	w, root, warnings := newWarnedWatcher(t, folders)
	startWatcher(t, w)
	return w, root, warnings
}

func startWatcher(t *testing.T, w *InstallWatcher) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
}

// pathScanner records the paths it is asked to scan.
type pathScanner struct {
	mu    sync.Mutex
	paths []string
}

func (s *pathScanner) Name() string               { return "skill-scanner" }
func (s *pathScanner) Version() string            { return "fake-1" }
func (s *pathScanner) SupportedTargets() []string { return []string{"skill"} }

func (s *pathScanner) Scan(_ context.Context, target string) (*scanner.ScanResult, error) {
	s.mu.Lock()
	s.paths = append(s.paths, target)
	s.mu.Unlock()
	return &scanner.ScanResult{Scanner: "skill-scanner", Target: target, Timestamp: time.Now().UTC()}, nil
}

func (s *pathScanner) scanned(dir string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, path := range s.paths {
		if filepath.Clean(path) == filepath.Clean(dir) {
			return true
		}
	}
	return false
}

func addSkill(t *testing.T, root, name string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: "+name+"\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// GAP-0905: a root admitted through group-writable folders of a private group
// while pam_group is loaded is published as a warning that names the folder,
// and with periodic rescan off a change under it still runs a scan of the
// root: a skill that admission did not see is scanned when another one changes.
func TestRootThroughGroupWritableFoldersIsRescannedOnEveryChange(t *testing.T) {
	w, root, warnings := newWarnedWatcher(t, []string{"/home/u/dotfiles"})
	addSkill(t, root, "before")
	probe := &pathScanner{}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return probe }
	startWatcher(t, w)
	select {
	case current := <-warnings:
		if len(current) != 1 || current[0].Path != root || len(current[0].Folders) != 1 || current[0].Folders[0] != "/home/u/dotfiles" {
			t.Fatalf("root warnings = %+v, want the root with its group-writable folder", current)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the warned root was not published")
	}
	if len(w.RootCoverageIssues()) != 0 {
		t.Fatalf("a warned root is admitted, not unavailable: %+v", w.RootCoverageIssues())
	}
	time.Sleep(500 * time.Millisecond)
	addSkill(t, root, "after")
	deadline := time.After(10 * time.Second)
	for !probe.scanned(filepath.Join(root, "before")) {
		select {
		case <-deadline:
			t.Fatal("a change under the warned root ran no scan of the root")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// A root with no group-writable folder on its route is watched as before: no
// warning and no extra rescan, with periodic rescan off.
func TestRootWithoutGroupWritableFoldersAsksNoExtraRescan(t *testing.T) {
	w, root, _ := newWarnedWatcher(t, nil)
	addSkill(t, root, "before")
	probe := &pathScanner{}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return probe }
	startWatcher(t, w)
	time.Sleep(500 * time.Millisecond)
	addSkill(t, root, "after")
	time.Sleep(1500 * time.Millisecond)
	if probe.scanned(filepath.Join(root, "before")) {
		t.Fatal("a change under an ordinary root rescanned a skill that did not change")
	}
	if len(w.RootWarnings()) != 0 {
		t.Fatalf("root warnings = %+v, want none", w.RootWarnings())
	}
}

// The warning goes away once the folders no longer carry the group write bit.
func TestRootWarningClearsWhenTheRouteIsFixed(t *testing.T) {
	w, root, warnings := runWarnedWatcher(t, []string{"/home/u/dotfiles"})
	select {
	case <-warnings:
	case <-time.After(5 * time.Second):
		t.Fatal("the warned root was not published")
	}
	stubRootRouteWarnings(t, nil)
	deadline := time.After(10 * time.Second)
	for {
		select {
		case current := <-warnings:
			if len(current) == 0 && !w.rootWarned(filepath.Join(root, "x")) {
				return
			}
		case <-deadline:
			t.Fatal("the warning stayed after the route was fixed")
		}
	}
}

// A flagged skill under a linked ~/.claude whose folders carry the default
// umask-002 mode is scanned and taken out. With the real proof on this
// account (a private group, local accounts) the 0775 route is admitted.
func TestFlaggedSkillUnderADefaultModeLinkedRootIsQuarantined(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.Skill.TakeAction = true
	home, root, physical := linkedAgentSkills(t)
	addSkill(t, physical, "bad")
	for _, dir := range []string{filepath.Join(home, "dotfiles"), filepath.Dir(physical), physical} {
		if err := os.Chmod(dir, 0o775); err != nil {
			t.Fatal(err)
		}
	}
	w := New(cfg, []string{root}, nil, store, logger, nil, nil)
	if _, _, err := rootRouteWarnings(root, watcherEvalSymlinks); err != nil {
		t.Skipf("the test account has no private group on local accounts: %v", err)
	}
	w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &countingScanner{name: "skill-scanner", findings: []scanner.Finding{{
			ID: "finding", RuleID: "TRUST-IGNORE-PREVIOUS", Severity: scanner.SeverityCritical, Title: "critical finding",
		}}}
	}
	res := w.runAdmission(context.Background(), InstallEvent{Type: InstallSkill, Name: "bad", Path: filepath.Join(root, "bad"), Timestamp: time.Now()})
	if res.Verdict != VerdictRejected {
		t.Fatalf("verdict=%s reason=%s, want the flagged skill rejected", res.Verdict, res.Reason)
	}
	if _, err := os.Stat(filepath.Join(physical, "bad")); !os.IsNotExist(err) {
		t.Fatalf("the flagged skill stayed in its folder (stat err %v)", err)
	}
}

// flaggedByNameScanner reports a critical finding for the skill folders named
// in flagged and a clean result for every other one, and signals each scan.
type flaggedByNameScanner struct {
	flagged map[string]bool
	scanned chan string
}

func (s *flaggedByNameScanner) Name() string               { return "skill-scanner" }
func (s *flaggedByNameScanner) Version() string            { return "fake-1" }
func (s *flaggedByNameScanner) SupportedTargets() []string { return []string{"skill"} }

func (s *flaggedByNameScanner) Scan(_ context.Context, target string) (*scanner.ScanResult, error) {
	result := &scanner.ScanResult{Scanner: "skill-scanner", Target: target, Timestamp: time.Now().UTC()}
	if s.flagged[filepath.Base(target)] {
		result.Findings = []scanner.Finding{{
			ID: "finding", RuleID: "TRUST-IGNORE-PREVIOUS", Severity: scanner.SeverityCritical, Title: "critical finding",
		}}
	}
	select {
	case s.scanned <- target:
	default:
	}
	return result, nil
}

// waitScanned waits until the scanner is asked to scan the skill folder name
// (by its resolved path under a linked root).
func (s *flaggedByNameScanner) waitScanned(t *testing.T, name string) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case target := <-s.scanned:
			if filepath.Base(target) == name {
				return
			}
		case <-deadline:
			t.Fatalf("skill %s was not scanned", name)
		}
	}
}

// waitGone waits until path no longer exists (the skill was taken out).
func waitGone(t *testing.T, path string) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		_, err := os.Lstat(path)
		if os.IsNotExist(err) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-deadline:
			t.Fatalf("%s was scanned and flagged but stayed in the admitted root", path)
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// GAP-0905: with periodic rescan off, a flagged skill that was in a root
// watched closely before the watcher started is scanned when another skill
// changes, and the verdict is enforced like an install: it is taken out of the
// folder, not only scanned. A clean skill beside it stays.
func TestWarnedRootRescanTakesOutAFlaggedSkillThatWasAlreadyThere(t *testing.T) {
	w, root, warnings := newWarnedWatcher(t, []string{"/home/u/dotfiles"})
	w.cfg.Gateway.Watcher.Skill.TakeAction = true
	addSkill(t, root, "before")
	addSkill(t, root, "fine")
	probe := &flaggedByNameScanner{flagged: map[string]bool{"before": true}, scanned: make(chan string, 16)}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return probe }
	startWatcher(t, w)
	select {
	case <-warnings:
	case <-time.After(5 * time.Second):
		t.Fatal("the warned root was not published")
	}
	time.Sleep(500 * time.Millisecond)
	addSkill(t, root, "after")
	probe.waitScanned(t, "before")
	waitGone(t, filepath.Join(root, "before"))
	probe.waitScanned(t, "fine")
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Lstat(filepath.Join(root, "fine")); err != nil {
		t.Fatalf("a clean skill under the warned root was taken out: %v", err)
	}
}

// The same flagged skill under a root with no group-writable folder is not
// rescanned by a change elsewhere (no extra cycle), and a flagged skill that
// is already admitted stays as before: only roots watched closely enforce.
func TestOrdinaryRootRescanLeavesAnUntouchedSkillAlone(t *testing.T) {
	w, root, _ := newWarnedWatcher(t, nil)
	w.cfg.Gateway.Watcher.Skill.TakeAction = true
	addSkill(t, root, "before")
	probe := &flaggedByNameScanner{flagged: map[string]bool{"before": true}, scanned: make(chan string, 16)}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return probe }
	startWatcher(t, w)
	time.Sleep(500 * time.Millisecond)
	addSkill(t, root, "after")
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Lstat(filepath.Join(root, "before")); err != nil {
		t.Fatalf("an untouched skill under an ordinary root was taken out: %v", err)
	}
}

// GAP-0905 on the reported layout: ~/.claude linked into a 0775 private-group
// dotfiles tree. With the real private-group proof the root is admitted, the
// PAM-loaded warning is supplied by the fixture, and a flagged skill that was
// already there is taken out of the linked folder by the warned rescan.
func TestWarnedLinkedRootRescanTakesOutAFlaggedSkillThatWasAlreadyThere(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Watch.RescanEnabled = false
	cfg.Gateway.Watcher.Skill.TakeAction = true
	home, root, physical := linkedAgentSkills(t)
	dotfiles := filepath.Join(home, "dotfiles")
	for _, dir := range []string{dotfiles, filepath.Dir(physical), physical} {
		if err := os.Chmod(dir, 0o775); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := rootRouteWarnings(root, watcherEvalSymlinks); err != nil {
		t.Skipf("the test account has no private group on local accounts: %v", err)
	}
	stubRootRouteWarnings(t, []string{dotfiles})
	addSkill(t, physical, "before")
	probe := &flaggedByNameScanner{flagged: map[string]bool{"before": true}, scanned: make(chan string, 16)}
	w := New(cfg, []string{root}, nil, store, logger, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return probe }
	warned := make(chan []RootWarning, 8)
	w.SetRootWarningHandler(func(current []RootWarning) { warned <- current })
	startWatcher(t, w)
	select {
	case current := <-warned:
		if len(current) != 1 {
			t.Fatalf("root warnings = %+v, want one", current)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the linked root warning was not published")
	}
	time.Sleep(500 * time.Millisecond)
	addSkill(t, physical, "after")
	probe.waitScanned(t, "before")
	waitGone(t, filepath.Join(physical, "before"))
}
