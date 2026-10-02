// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

// GAP-1243: Claude Code's account-synced container is expanded into its
// skills instead of being scanned (and failing) as one skill.
func TestEnumerateTargetsExpandsClaudeSyncedSkills(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	root := filepath.Join(t.TempDir(), ".claude", "skills")
	account := filepath.Join(root, "synced", "7e6ed31d-account")
	for _, dir := range []string{
		filepath.Join(root, "own"),
		filepath.Join(account, "pdf"),
		filepath.Join(account, "docx"),
		filepath.Join(account, "unmarked"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if filepath.Base(dir) != "unmarked" {
			if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# skill\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(root, "synced", "manifest.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := &InstallWatcher{cfg: cfg, skillDirs: []string{root}, store: store, logger: logger}

	var got []string
	for _, target := range w.enumerateTargets() {
		if target.Type == InstallSkill {
			got = append(got, target.Name+"="+target.Path)
		}
	}
	sort.Strings(got)
	want := []string{
		"docx=" + filepath.Join(account, "docx"),
		"own=" + filepath.Join(root, "own"),
		"pdf=" + filepath.Join(account, "pdf"),
	}
	if len(got) != len(want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("targets = %v, want %v", got, want)
		}
	}

	events := w.pendingInstallEvents(filepath.Join(root, "synced"))
	if len(events) != 2 {
		t.Fatalf("pending events for synced container = %+v, want its 2 skills", events)
	}
	for _, evt := range events {
		if evt.Type != InstallSkill || filepath.Dir(evt.Path) != account {
			t.Fatalf("unexpected synced event %+v", evt)
		}
	}
}

// GAP-1409: a skill synced into an existing account folder, or a new account
// folder with a skill, is admitted on arrival rather than at the next rescan.
func TestWatcherAdmitsSkillSyncedIntoAccountFolder(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	root := filepath.Join(t.TempDir(), ".claude", "skills")
	account := filepath.Join(root, "synced", "acct-1")
	if err := os.MkdirAll(account, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"live-skill", "second-skill"} {
		if err := store.SetActionField("skill", name, "install", "allow", "pre-approved"); err != nil {
			t.Fatal(err)
		}
	}

	var mu sync.Mutex
	seen := map[string]string{}
	w := New(cfg, []string{root}, nil, store, logger, nil, func(r AdmissionResult) {
		mu.Lock()
		seen[r.Event.Name] = r.Event.Path
		mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- w.Run(ctx) }()
	time.Sleep(500 * time.Millisecond)

	writeSkill := func(dir string) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# skill\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeSkill(filepath.Join(account, "live-skill"))
	writeSkill(filepath.Join(root, "synced", "acct-2", "second-skill"))

	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		n := len(seen)
		mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			cancel()
			<-errCh
			mu.Lock()
			defer mu.Unlock()
			t.Fatalf("admissions = %v, want live-skill and second-skill", seen)
		case <-time.After(50 * time.Millisecond):
		}
	}
	cancel()
	<-errCh
	mu.Lock()
	defer mu.Unlock()
	if seen["live-skill"] != filepath.Join(account, "live-skill") ||
		seen["second-skill"] != filepath.Join(root, "synced", "acct-2", "second-skill") {
		t.Fatalf("admissions = %v", seen)
	}
}
