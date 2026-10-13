// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1063: a session in a project registers the project's skill folder for
// the install watcher, and a skill there is refused until install admission
// has recorded it, then judged as usual.
func TestProjectSkillIsHeldUntilItsFirstAdmission(t *testing.T) {
	store, logger := newNativeSkillRuntimeTestStore(t)
	home := t.TempDir()
	project := filepath.Join(home, "proj", "ucc-app")
	skills := filepath.Join(project, ".claude", "skills")
	skill := filepath.Join(skills, "ucc-flagged-skill2")
	for _, dir := range []string{skill, filepath.Join(project, ".git")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: ucc-flagged-skill2\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots := &projectSkillRoots{}
	roots.start(true)
	for i := 0; i < 32; i++ {
		if !roots.add("claude-code", filepath.Join(home, "older-projects", string(rune('a'+i)), ".claude", "skills")) {
			t.Fatalf("could not register earlier project root %d", i)
		}
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	api := &APIServer{store: store, logger: logger, scannerCfg: cfg, projectSkills: roots}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1004, Home: home})
	call := func() (config.AssetPolicyDecision, bool) {
		return api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Skill", CWD: project,
			ToolInput: map[string]interface{}{"skill": "ucc-flagged-skill2"},
		})
	}
	if decision, matched := call(); !matched || decision.Action != "block" {
		t.Fatalf("unadmitted project skill = %+v, matched=%v; want refused", decision, matched)
	}
	realSkills, err := filepath.EvalSymlinks(skills)
	if err != nil {
		t.Fatal(err)
	}
	if !roots.registered(realSkills) {
		t.Fatalf("project skill folder %s was not registered for the watcher", realSkills)
	}
	if err := store.SetTargetSnapshot("skill", filepath.Join(realSkills, filepath.Base(skill)), "h", "{}", "{}", "[]", "scan-1", "fp"); err != nil {
		t.Fatal(err)
	}
	if decision, matched := call(); matched {
		t.Fatalf("admitted project skill = %+v, want it judged as usual", decision)
	}
}

// GAP-1297: a link below a managed caller's home that points at another
// user's project is not registered, so the watcher never scans that tree.
func TestManagedProjectSkillLinkOutsideHomeIsNotRegistered(t *testing.T) {
	root := t.TempDir()
	home, other := filepath.Join(root, "alice"), filepath.Join(root, "bob", "proj")
	for _, dir := range []string{home, filepath.Join(other, ".claude", "skills"), filepath.Join(other, ".git")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(home, "proj")
	if err := os.Symlink(other, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	roots := &projectSkillRoots{}
	roots.start(true)
	api := &APIServer{scannerCfg: &config.Config{}, projectSkills: roots}
	api.noteProjectSkillFolders(withManagedHookPeer(context.Background(), managedHookPeer{UID: 1004, Home: home}), "claudecode", link)
	realOther, err := filepath.EvalSymlinks(filepath.Join(other, ".claude", "skills"))
	if err != nil {
		t.Fatal(err)
	}
	if roots.registered(filepath.Join(link, ".claude", "skills")) || roots.registered(realOther) {
		t.Fatal("a project link below the caller's home registered another user's skill folder")
	}
}

// GAP-1375: a skill in a registered project folder that the gateway cannot
// stat for any reason but its absence (access denied, a sharing violation)
// stays refused; only a skill that is gone is not held.
func TestProjectSkillThatCannotBeCheckedStaysRefused(t *testing.T) {
	restore := projectSkillLstat
	t.Cleanup(func() { projectSkillLstat = restore })
	store, logger := newNativeSkillRuntimeTestStore(t)
	skills := filepath.Join(t.TempDir(), "proj", ".claude", "skills")
	roots := &projectSkillRoots{}
	roots.start(true)
	if !roots.add("claudecode", skills) {
		t.Fatal("could not register the project skill folder")
	}
	api := &APIServer{store: store, logger: logger, projectSkills: roots}
	skill := filepath.Join(skills, "locked-skill")
	for _, tc := range []struct {
		err  error
		held bool
	}{{fs.ErrPermission, true}, {fs.ErrNotExist, false}} {
		projectSkillLstat = func(path string) (fs.FileInfo, error) {
			return nil, &fs.PathError{Op: "lstat", Path: path, Err: tc.err}
		}
		decision, held := api.projectSkillScanPending("skill", "claudecode", "hook", []string{skill})
		if held != tc.held || (held && decision.Action != "block") {
			t.Fatalf("lstat %v: decision=%+v held=%v; want held=%v", tc.err, decision, held, tc.held)
		}
	}
}

// GAP-1377: disabling the watcher by hot reload stops project skill
// admission, as a cold start with that config does: no folder is
// registered and a new project skill is not held as pending.
func TestDisabledWatcherStopsProjectSkillAdmission(t *testing.T) {
	store, logger := newNativeSkillRuntimeTestStore(t)
	skills := filepath.Join(t.TempDir(), "proj", ".claude", "skills")
	skill := filepath.Join(skills, "new-skill")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Gateway.Watcher.Enabled = false
	s := &Sidecar{cfg: cfg, health: NewSidecarHealth()}
	s.projectSkills.start(true) // the watcher that ran before the reload
	s.projectSkills.add("claudecode", skills)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.runWatcher(ctx); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{store: store, logger: logger, projectSkills: &s.projectSkills}
	if decision, held := api.projectSkillScanPending("skill", "claudecode", "hook", []string{skill}); held {
		t.Fatalf("new project skill after the watcher was disabled = %+v; want not held", decision)
	}
	if s.projectSkills.add("claudecode", filepath.Join(t.TempDir(), "other", ".claude", "skills")) {
		t.Fatal("a project skill folder was registered with the watcher disabled")
	}
}
