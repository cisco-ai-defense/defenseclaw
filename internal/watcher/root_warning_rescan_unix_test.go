//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
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

func runWarnedWatcher(t *testing.T, folders []string) (*InstallWatcher, string, chan []RootWarning) {
	t.Helper()
	cfg, store, logger, root := setupTestEnv(t)
	cfg.Watch.RescanEnabled = false
	stubRootRouteWarnings(t, folders)
	warnings := make(chan []RootWarning, 8)
	w := New(cfg, []string{root}, nil, store, logger, nil, nil)
	w.SetRootWarningHandler(func(current []RootWarning) { warnings <- current })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	return w, root, warnings
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
// and every change under it asks for a rescan.
func TestRootThroughGroupWritableFoldersIsRescannedOnEveryChange(t *testing.T) {
	w, root, warnings := runWarnedWatcher(t, []string{"/home/u/dotfiles"})
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
	for _, name := range []string{"one", "two"} {
		addSkill(t, root, name)
		select {
		case <-w.rescanNow:
		case <-time.After(5 * time.Second):
			t.Fatalf("a change under the warned root (%s) asked for no rescan", name)
		}
	}
}

// A root with no group-writable folder on its route is watched as before: no
// warning and no extra rescan.
func TestRootWithoutGroupWritableFoldersAsksNoExtraRescan(t *testing.T) {
	w, root, _ := runWarnedWatcher(t, nil)
	time.Sleep(500 * time.Millisecond)
	addSkill(t, root, "one")
	select {
	case <-w.rescanNow:
		t.Fatal("a change under an ordinary root asked for a rescan")
	case <-time.After(1500 * time.Millisecond):
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
