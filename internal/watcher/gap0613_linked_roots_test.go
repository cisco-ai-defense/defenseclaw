// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/fsnotify/fsnotify"
)

func TestGAP0613SharedRootCoverageKeepsAssetKindsSeparate(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	root := filepath.Join(t.TempDir(), "shared")
	w := New(cfg, []string{root}, []string{root}, store, logger, nil, nil)
	w.SetRootConnectors(map[string]string{root: "claudecode"})
	w.SetRootConsumers([]RootConsumer{
		{Kind: "skill", Path: root, Connector: "claudecode"},
		{Kind: "skill", Path: root, Connector: "amp"},
		{Kind: "plugin", Path: root, Connector: "claudecode"},
	})
	w.setRootCoverage("skill", root, errors.New("unavailable"))
	w.setRootCoverage("plugin", root, errors.New("unavailable"))
	issues := w.RootCoverageIssues()
	if len(issues) != 2 || w.connectorForPath(filepath.Join(root, "ordinary")) != "claudecode" {
		t.Fatalf("shared root coverage = %+v", issues)
	}
	for _, issue := range issues {
		switch issue.Kind {
		case "skill":
			if !slices.Equal(issue.Connectors, []string{"claudecode", "amp"}) {
				t.Errorf("skill consumers = %v", issue.Connectors)
			}
		case "plugin":
			if !slices.Equal(issue.Connectors, []string{"claudecode"}) {
				t.Errorf("plugin consumers = %v", issue.Connectors)
			}
		default:
			t.Errorf("unexpected coverage issue = %+v", issue)
		}
	}
	w.setRootCoverage("skill", root, nil)
	if remaining := w.RootCoverageIssues(); len(remaining) != 1 || remaining[0].Kind != "plugin" {
		t.Errorf("plugin root coverage after skill recovery = %+v", remaining)
	}
}

func TestGAP0613LinkedAgentDirectoryAdmitsAndQuarantinesNewSkill(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership checks")
	}
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cfg.Watch.RescanEnabled = true
	cfg.Gateway.Watcher.Skill.TakeAction = true
	home := t.TempDir()
	realRoot := filepath.Join(home, "dotfiles", "claude-dir", "skills")
	if err := os.MkdirAll(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(realRoot), filepath.Join(home, ".claude")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	root := filepath.Join(home, ".claude", "skills")
	admitted := make(chan AdmissionResult, 4)
	w := New(cfg, []string{root}, nil, store, logger, nil, func(result AdmissionResult) { admitted <- result })
	w.SetRootConnectors(map[string]string{root: "claudecode"})
	w.scannerFactory = func(evt InstallEvent) scanner.Scanner {
		if evt.Name == "flagged" {
			return &countingScanner{name: "skill-scanner", findings: []scanner.Finding{{
				ID: "finding", RuleID: "TRUST-IGNORE-PREVIOUS", Severity: scanner.SeverityCritical, Title: "critical finding",
			}}}
		}
		return &countingScanner{name: "skill-scanner"}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.After(5 * time.Second)
	for !w.firstCycleDone.Load() {
		select {
		case <-deadline:
			t.Fatal("watcher did not complete its first cycle")
		case <-time.After(10 * time.Millisecond):
		}
	}
	for _, name := range []string{"flagged", "ordinary"} {
		skill := filepath.Join(realRoot, name)
		if err := os.Mkdir(skill, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: "+name+"\n---\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	results := make(map[string]AdmissionResult)
	for len(results) < 2 {
		select {
		case result := <-admitted:
			results[result.Event.Name] = result
		case <-deadline:
			t.Fatalf("admissions received: %+v", results)
		}
	}
	if results["flagged"].Verdict != VerdictRejected || results["ordinary"].Verdict != VerdictClean ||
		results["ordinary"].RuntimeAction != "allow" {
		t.Fatalf("linked root admissions: %+v", results)
	}
	if _, err := os.Lstat(filepath.Join(realRoot, "flagged")); !os.IsNotExist(err) {
		t.Fatalf("flagged skill stayed in the linked root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(realRoot, "ordinary")); err != nil {
		t.Fatalf("ordinary skill was removed: %v", err)
	}
}

func TestGAP0613AccountOwnedLinkedSkillRootsAreWatchedAndEnumerated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership checks")
	}
	for _, tc := range []struct {
		name, agentDir string
	}{
		{"claudecode", ".claude"},
		{"codex", ".codex"},
		{"opencode", ".config/opencode"},
		{"cursor", ".cursor"},
		{"hermes", ".hermes"},
	} {
		for _, linked := range []bool{false, true} {
			name := tc.name + "/plain"
			if linked {
				name = tc.name + "/linked"
			}
			t.Run(name, func(t *testing.T) {
				cfg, store, logger, _ := setupTestEnv(t)
				cfg.Guardrail.Connector = tc.name
				home := t.TempDir()
				agentDir := filepath.Join(home, tc.agentDir)
				if linked {
					realDir := filepath.Join(home, "dotfiles", tc.name)
					if err := os.MkdirAll(realDir, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.MkdirAll(filepath.Dir(agentDir), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(realDir, agentDir); err != nil {
						t.Skipf("symlinks unavailable: %v", err)
					}
				}
				root := filepath.Join(agentDir, "skills")
				skill := filepath.Join(root, "ordinary")
				if err := os.MkdirAll(skill, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: ordinary\n---\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				fsw, err := fsnotify.NewWatcher()
				if err != nil {
					t.Fatal(err)
				}
				defer fsw.Close()
				if _, err := ensureAndWatch(fsw, root); err != nil {
					t.Fatalf("watch skill root: %v", err)
				}
				w := New(cfg, []string{root}, nil, store, logger, nil, nil)
				targets := w.enumerateTargets()
				found := false
				for _, target := range targets {
					if target.Path == skill {
						found = true
					}
				}
				if !found {
					t.Fatalf("skill %s absent from rescan targets: %+v", skill, targets)
				}
			})
		}
	}
}

func TestGAP0613AccountOwnedFinalSkillRootLinkIsEnumerated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership checks")
	}
	for _, agent := range []string{".claude", ".cursor", ".hermes"} {
		t.Run(agent, func(t *testing.T) {
			cfg, store, logger, _ := setupTestEnv(t)
			home := t.TempDir()
			root := filepath.Join(home, agent, "skills")
			realRoot := filepath.Join(home, "dotfiles", agent, "skills")
			if err := os.MkdirAll(filepath.Join(realRoot, "ordinary"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(realRoot, "ordinary", "SKILL.md"), []byte("# ordinary\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(realRoot, root); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			fsw, err := fsnotify.NewWatcher()
			if err != nil {
				t.Fatal(err)
			}
			defer fsw.Close()
			if _, err := ensureAndWatch(fsw, root); err != nil {
				t.Fatalf("watch linked root: %v", err)
			}
			w := New(cfg, []string{root}, nil, store, logger, nil, nil)
			found := false
			for _, evt := range w.enumerateTargets() {
				if evt.Path == filepath.Join(root, "ordinary") {
					found = true
				}
			}
			if !found {
				t.Fatal("skill under the linked final root was not enumerated")
			}
		})
	}
}

func TestGAP0613UntrustedSkillRootLinksStayUnavailable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership checks")
	}
	for _, tc := range []struct {
		name   string
		target func(*testing.T, string) string
	}{
		{"world-writable-target", func(t *testing.T, home string) string {
			t.Helper()
			dir := filepath.Join(home, "shared")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}
			return dir
		}},
		{"other-account-target", func(_ *testing.T, _ string) string { return "/etc" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			root := filepath.Join(home, ".claude", "skills")
			if err := os.Symlink(tc.target(t, home), filepath.Dir(root)); err != nil {
				t.Fatal(err)
			}
			fsw, err := fsnotify.NewWatcher()
			if err != nil {
				t.Fatal(err)
			}
			defer fsw.Close()
			if _, err := ensureAndWatch(fsw, root); err == nil || len(fsw.WatchList()) != 0 {
				t.Fatalf("untrusted root watch = %v, watches %v", err, fsw.WatchList())
			}
		})
	}
}

func TestGAP0613UnavailableRootReportsAndRecovers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership checks")
	}
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
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
	changes := make(chan []RootCoverageIssue, 4)
	w := New(cfg, []string{root}, nil, store, logger, nil, nil)
	w.SetRootConnectors(map[string]string{root: "claudecode"})
	w.SetRootCoverageHandler(func(issues []RootCoverageIssue) { changes <- issues })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case issues := <-changes:
		if len(issues) != 1 || issues[0].Connector != "claudecode" || issues[0].Path != root {
			t.Fatalf("unavailable root coverage = %+v", issues)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("unavailable root was not reported")
	}
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	select {
	case issues := <-changes:
		if len(issues) != 0 || len(w.RootCoverageIssues()) != 0 {
			t.Fatalf("recovered root coverage = %+v", issues)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("recovered root stayed unavailable")
	}
}
