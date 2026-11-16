// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hermesskills"
	"github.com/fsnotify/fsnotify"
)

// The last skill in a moved category must still receive its own admission
// after a bounded discovery reaches the real directory limit.
func TestNestedSkillMoveInBeyondDirectoryLimit(t *testing.T) {
	for _, tc := range []struct{ name, rootDir string }{
		{"hermes", ".hermes"},
		{"cursor", ".cursor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantName := "blocked-skill"
			if tc.name == "cursor" {
				wantName = "zz-blocked-skill"
			}
			cfg, store, logger, _ := setupTestEnv(t)
			cfg.Guardrail.Connector = tc.name
			root := filepath.Join(t.TempDir(), tc.rootDir, "skills")
			category := filepath.Join(root, "drop")
			if err := os.MkdirAll(category, 0o700); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < nestedSkillDirectoryLimit; i++ {
				if err := os.Mkdir(filepath.Join(category, fmt.Sprintf("d%05d", i)), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			blocked := filepath.Join(category, "zz-blocked-skill")
			if err := os.Mkdir(blocked, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(blocked, "SKILL.md"), []byte("---\nname: blocked-skill\n---\n# test\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			w := New(cfg, []string{root}, nil, store, logger, nil, nil)
			events := w.pendingInstallEvents(category)
			if len(events) != 1 || events[0].Path != blocked || events[0].Name != wantName {
				t.Fatalf("cap discovery = %+v; want only blocked nested skill", events)
			}
			targets := w.enumerateTargets()
			if len(targets) != 1 || targets[0].Path != blocked {
				t.Fatalf("cap rescan = %+v; want blocked nested skill", targets)
			}
		})
	}
}

func TestNestedSkillMoveInBeyondDepthLimit(t *testing.T) {
	for _, tc := range []struct{ name, rootDir string }{
		{"hermes", ".hermes"}, {"cursor", ".cursor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, logger, _ := setupTestEnv(t)
			cfg.Guardrail.Connector = tc.name
			root := filepath.Join(t.TempDir(), tc.rootDir, "skills")
			category := filepath.Join(root, "drop")
			skill := category
			for i := 0; i <= nestedSkillDepthLimit; i++ {
				skill = filepath.Join(skill, "d")
			}
			if err := os.MkdirAll(skill, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("# deep skill\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			w := New(cfg, []string{root}, nil, store, logger, nil, nil)
			events := w.pendingInstallEvents(category)
			if len(events) != 1 || events[0].Path != skill {
				t.Fatalf("depth fallback = %+v, want marked skill", events)
			}
		})
	}
}

func TestSecureClientCursorSyncedSkillKeepsSingleTarget(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "cursor"
	cfg.DeploymentMode = "managed_enterprise"
	cfg.Enterprise.Profile = "secure_client"
	root := filepath.Join(t.TempDir(), ".claude", "skills")
	account := filepath.Join(root, "synced", "account")
	for _, name := range []string{"old-skill", "new-skill"} {
		skill := filepath.Join(account, name)
		if err := os.MkdirAll(skill, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("# test\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w := New(cfg, []string{root}, nil, store, logger, nil, nil)
	newSkill := filepath.Join(account, "new-skill")
	if skill, inside := w.changedSkillFolder(newSkill); inside {
		t.Fatalf("Secure Client mapped synced create to %s", skill)
	}
	events := w.pendingInstallEvents(newSkill)
	if len(events) != 1 || events[0].Path != newSkill {
		t.Fatalf("Secure Client synced create = %+v, want only new skill", events)
	}
}

func TestWatcherLargeMovedCategoryReaderStall(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "hermes"
	cfg.Watch.RescanEnabled = false
	cfg.Gateway.Watcher.Skill.TakeAction = true
	cfg.AssetPolicy.Skill.Allowed = []config.AssetPolicyRule{{Name: "drop", Reason: "test policy"}, {Name: "quick", Reason: "test policy"}}
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "blocked-skill", Reason: "test policy"}}
	home := t.TempDir()
	root := filepath.Join(home, ".hermes", "skills")
	staged := filepath.Join(home, "staged-drop")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(staged, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < nestedSkillDirectoryLimit; i++ {
		if err := os.Mkdir(filepath.Join(staged, fmt.Sprintf("d%05d", i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	blocked := filepath.Join(staged, "zz-blocked-skill")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "SKILL.md"), []byte("---\nname: blocked-skill\n---\n# test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(root, "drop")
	quick := filepath.Join(root, "quick")
	second := filepath.Join(root, "second")
	watchProgress := make(chan struct{}, 1)
	releaseWatch := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(releaseWatch)
		}
	}()
	quickRead := make(chan struct{}, 1)
	secondRead := make(chan struct{}, 1)
	admitted := make(chan AdmissionResult, 4)
	watchEvents := &watcherTestRuntime{}
	logger.SetRuntimeV8Emitter(watchEvents)
	w := New(cfg, []string{root}, nil, store, logger, nil, func(result AdmissionResult) { admitted <- result })
	w.onNestedWatchProgress = func(path string) {
		if path == moved {
			select {
			case watchProgress <- struct{}{}:
			default:
			}
			<-releaseWatch
		}
	}
	w.onReadEvent = func(event fsnotify.Event) {
		if event.Op&fsnotify.Create == 0 {
			return
		}
		switch event.Name {
		case quick:
			select {
			case quickRead <- struct{}{}:
			default:
			}
		case second:
			select {
			case secondRead <- struct{}{}:
			default:
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	waitForSkillWatchStart(t, watchEvents)
	if err := os.Rename(staged, moved); err != nil {
		t.Fatal(err)
	}
	// The traversal registers one watch per directory of a 32,768-directory
	// category; how long that takes is the runner's speed, not a property of
	// the watcher. Wait for the event and fail only at the test binary's own
	// deadline.
	select {
	case <-watchProgress:
	case <-testDeadlineGuard(t):
		t.Fatal("large moved category watch did not reach 1,024 directories")
	}
	// Keep the traversal worker parked at directory 1,024. Reading a second
	// root event proves the reader finished handling the first one while the
	// worker was held. The timeout is only a deadlock guard; a wall-clock
	// measurement includes runner scheduling and notification delivery.
	readerDeadline := time.After(100 * w.debounce)
	if err := os.Mkdir(quick, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(quick, "SKILL.md"), []byte("# quick\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-quickRead:
	case <-readerDeadline:
		t.Fatal("reader did not read unrelated create while traversal was held")
	}
	if err := os.Mkdir(second, 0o700); err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondRead:
	case <-readerDeadline:
		t.Fatal("reader did not finish unrelated create while traversal was held")
	}
	close(releaseWatch)
	released = true
	wantBlocked := filepath.Join(moved, "zz-blocked-skill")
	gotBlocked, gotAllowed := false, false
	// Discovery of the moved category walks all 32,768 directories (twice, once
	// to the bounded limit and once for the full scan); wait for the two
	// admissions themselves, not for a wall-clock estimate of that walk.
	deadline := testDeadlineGuard(t)
	for !gotBlocked || !gotAllowed {
		select {
		case result := <-admitted:
			switch result.Event.Path {
			case wantBlocked:
				if result.Event.Name != "blocked-skill" || result.Verdict != VerdictBlocked {
					t.Fatalf("large move admission = %+v; want blocked nested skill", result)
				}
				gotBlocked = true
			case quick:
				if result.Verdict != VerdictAllowed {
					t.Fatalf("unrelated skill admission = %+v; want allowed", result)
				}
				gotAllowed = true
			}
		case <-deadline:
			t.Fatalf("admissions after traversal: blocked=%t allowed=%t", gotBlocked, gotAllowed)
		}
	}
}

// A completed skill moved into a category has no file create events for its
// contents. The directory event itself must reach admission.
func TestWatcherAdmitsNestedSkillMoveIn(t *testing.T) {
	for _, tc := range []struct {
		name, rootDir string
	}{
		{"hermes", ".hermes"},
		{"cursor", ".cursor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, logger, _ := setupTestEnv(t)
			cfg.Guardrail.Connector = tc.name
			cfg.Gateway.Watcher.Skill.TakeAction = true
			cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "blocked-skill", Reason: "test policy"}}
			home := t.TempDir()
			root := filepath.Join(home, tc.rootDir, "skills")
			category := filepath.Join(root, "productivity")
			staged := filepath.Join(home, "staged-skill")
			for _, dir := range []string{category, staged} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(staged, "SKILL.md"), []byte("---\nname: blocked-skill\n---\n# test\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			admitted := make(chan AdmissionResult, 4)
			watchEvents := &watcherTestRuntime{}
			logger.SetRuntimeV8Emitter(watchEvents)
			w := New(cfg, []string{root}, nil, store, logger, nil, func(result AdmissionResult) { admitted <- result })
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- w.Run(ctx) }()
			t.Cleanup(func() { cancel(); <-done })
			waitForSkillWatchStart(t, watchEvents)

			moved := filepath.Join(category, "blocked-skill")
			if err := os.Rename(staged, moved); err != nil {
				t.Fatal(err)
			}
			select {
			case result := <-admitted:
				if result.Event.Path != moved || result.Event.Name != "blocked-skill" || result.Verdict != VerdictBlocked {
					t.Fatalf("admission = %+v; want blocked nested skill", result)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("nested moved-in skill received no watcher admission")
			}
			if _, err := os.Lstat(moved); !os.IsNotExist(err) {
				t.Fatalf("blocked nested skill remains in place: %v", err)
			}
		})
	}
}

// A moved category produces one directory notification and may already hold
// several skills at different depths. Admit the marked folders, not the
// category itself.
func TestWatcherExpandsMovedNestedSkillCategory(t *testing.T) {
	for _, tc := range []struct {
		name, rootDir string
	}{
		{"hermes", ".hermes"},
		{"cursor", ".cursor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, logger, _ := setupTestEnv(t)
			cfg.Guardrail.Connector = tc.name
			for _, name := range []string{"first", "second"} {
				cfg.AssetPolicy.Skill.Allowed = append(cfg.AssetPolicy.Skill.Allowed,
					config.AssetPolicyRule{Name: name, Reason: "test policy"})
			}
			home := t.TempDir()
			root := filepath.Join(home, tc.rootDir, "skills")
			category := filepath.Join(root, "productivity", "area", "research")
			staged := filepath.Join(home, "staged-category")
			for _, dir := range []string{category, filepath.Join(staged, "first"), filepath.Join(staged, "deeper", "second")} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for _, skill := range []string{filepath.Join(staged, "first"), filepath.Join(staged, "deeper", "second")} {
				name := filepath.Base(skill)
				if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: "+name+"\n---\n# test\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			watchEvents := &watcherTestRuntime{}
			logger.SetRuntimeV8Emitter(watchEvents)
			admitted := make(chan AdmissionResult, 8)
			w := New(cfg, []string{root}, nil, store, logger, nil, func(result AdmissionResult) { admitted <- result })
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- w.Run(ctx) }()
			t.Cleanup(func() { cancel(); <-done })
			waitForSkillWatchStart(t, watchEvents)

			moved := filepath.Join(category, "drop")
			if err := os.Rename(staged, moved); err != nil {
				t.Fatal(err)
			}
			want := map[string]string{
				"first":  filepath.Join(moved, "first"),
				"second": filepath.Join(moved, "deeper", "second"),
			}
			deadline := time.After(3 * time.Second)
			for len(want) > 0 {
				select {
				case result := <-admitted:
					path, ok := want[result.Event.Name]
					if !ok || result.Event.Path != path || result.Verdict != VerdictAllowed {
						t.Fatalf("unexpected category admission: %+v; remaining=%v", result, want)
					}
					delete(want, result.Event.Name)
				case <-deadline:
					t.Fatalf("moved category skills not admitted: %v", want)
				}
			}
		})
	}
}

// testDeadlineGuard fires when nine tenths of the time left before the test
// binary's own -timeout have passed, so a watcher that never produces the
// event a test waits for fails with the test's message and not with the
// binary's panic. It never fires when the binary has no deadline.
func testDeadlineGuard(t *testing.T) <-chan time.Time {
	t.Helper()
	deadline, ok := t.Deadline()
	if !ok {
		return nil
	}
	return time.After(time.Until(deadline) / 10 * 9)
}

func waitForSkillWatchStart(t *testing.T, runtime *watcherTestRuntime) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		logs, _ := runtime.snapshot()
		if len(logs) > 0 {
			return
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatal("watcher did not start")
		}
	}
}

func TestRecursiveSkillRootsResolveNestedEditsAndRescan(t *testing.T) {
	for _, tc := range []struct {
		name, rootDir string
	}{
		{"hermes", ".hermes"},
		{"cursor", ".cursor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, logger, _ := setupTestEnv(t)
			cfg.Guardrail.Connector = tc.name
			root := filepath.Join(t.TempDir(), tc.rootDir, "skills")
			skill := filepath.Join(root, "category", "deeper", "real-skill")
			if err := os.MkdirAll(skill, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("# test\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			w := New(cfg, []string{root}, nil, store, logger, nil, nil)
			if got, ok := w.changedSkillFolder(filepath.Join(skill, "scripts", "helper.py")); !ok || got != skill {
				t.Fatalf("nested edit resolves to %q, %v; want %q", got, ok, skill)
			}
			var found bool
			for _, evt := range w.enumerateTargets() {
				if evt.Path == skill && evt.Type == InstallSkill {
					found = true
				}
				if evt.Path == filepath.Join(root, "category") {
					t.Fatal("category was enumerated as a skill")
				}
			}
			if !found {
				t.Fatal("nested skill missing from rescan")
			}
		})
	}
}

func TestRecursiveSkillDiscoveryRejectsLinkedCategory(t *testing.T) {
	home := t.TempDir()
	outside := filepath.Join(home, "outside", "skill")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "SKILL.md"), []byte("# test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, rootDir string
	}{
		{"hermes", ".hermes"},
		{"cursor", ".cursor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(home, tc.rootDir, "skills")
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			linked := filepath.Join(root, "category")
			if err := os.Symlink(filepath.Dir(outside), linked); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			var err error
			if tc.name == "hermes" {
				_, err = hermesskills.DiscoverUnder(root, linked, 8)
			} else {
				_, err = cursorSkillFolders(root, linked)
			}
			if err == nil {
				t.Fatal("linked category was accepted for subtree discovery")
			}
		})
	}
}

func TestSkillDiscoveryRejectsUntrustedLinkedRoot(t *testing.T) {
	for _, tc := range []struct {
		name, rootDir string
	}{
		{"cursor", ".cursor"},
		{"hermes", ".hermes"},
		{"flat", ".codex"},
	} {
		for _, linkParent := range []bool{false, true} {
			name := tc.name + "/root"
			if linkParent {
				name = tc.name + "/parent"
			}
			t.Run(name, func(t *testing.T) {
				home := t.TempDir()
				outside := filepath.Join(home, "outside")
				skill := filepath.Join(outside, "category", "skill")
				if err := os.MkdirAll(skill, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("# test\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				direct := filepath.Join(outside, "direct")
				if err := os.Mkdir(direct, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(direct, "SKILL.md"), []byte("# test\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				parent := filepath.Join(home, tc.rootDir)
				root := filepath.Join(parent, "skills")
				if linkParent {
					if err := os.Chmod(home, 0o777); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(home, parent); err != nil {
						t.Skipf("symlink unavailable: %v", err)
					}
					// The parent link must lead to an existing skills tree.
					if err := os.Rename(outside, filepath.Join(home, "skills")); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Chmod(outside, 0o777); err != nil {
						t.Fatal(err)
					}
					if err := os.MkdirAll(parent, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, root); err != nil {
						t.Skipf("symlink unavailable: %v", err)
					}
				}
				category := filepath.Join(root, "category")
				if tc.name == "cursor" {
					if paths, err := cursorSkillFolders(root, category); err == nil || len(paths) != 0 {
						t.Fatalf("linked Cursor root discovery = %v, %v; want error and no skills", paths, err)
					}
				}
				cfg, store, logger, _ := setupTestEnv(t)
				w := New(cfg, []string{root}, nil, store, logger, nil, nil)
				if got := w.enumerateTargets(); len(got) != 0 {
					t.Fatalf("linked root rescan targets = %+v", got)
				}
				pendingPath := category
				if tc.name == "flat" {
					pendingPath = filepath.Join(root, "direct")
				}
				if got := w.pendingInstallEvents(pendingPath); len(got) != 0 {
					t.Fatalf("linked root pending events = %+v", got)
				}
				fsw, err := fsnotify.NewWatcher()
				if err != nil {
					t.Fatal(err)
				}
				defer fsw.Close()
				if _, err := ensureAndWatch(fsw, root); err == nil || len(fsw.WatchList()) != 0 {
					t.Fatalf("linked root watch = %v, watches %v; want refusal", err, fsw.WatchList())
				}
			})
		}
	}
}

func TestGAP0504DeniedParentStillWatchesAndRescansPlainRoot(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, ".hermes", "skills")
	skill := filepath.Join(root, "section", "ordinary")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: ordinary\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := watcherEvalSymlinks
	t.Cleanup(func() { watcherEvalSymlinks = previous })
	watcherEvalSymlinks = func(string) (string, error) {
		return "", &fs.PathError{Op: "resolve", Path: root, Err: fs.ErrPermission}
	}
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer fsw.Close()
	if _, err := ensureAndWatch(fsw, root); err != nil || len(fsw.WatchList()) != 1 {
		t.Fatalf("plain root watch = %v, watches %v", err, fsw.WatchList())
	}
	cfg, store, logger, _ := setupTestEnv(t)
	w := New(cfg, []string{root}, nil, store, logger, nil, nil)
	targets := w.enumerateTargets()
	if len(targets) != 1 || targets[0].Path != skill {
		t.Fatalf("plain root rescan targets = %+v", targets)
	}
	if err := unlinkedSkillTreePath(root, skill); err != nil {
		t.Fatalf("plain subtree refused: %v", err)
	}
	unsafe := filepath.Join(home, "unsafe")
	if err := os.MkdirAll(filepath.Join(unsafe, "skills"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(home, "linked")
	if err := os.Symlink(unsafe, linked); err == nil {
		if err := unlinkedSkillTreePath(filepath.Join(linked, "skills"), filepath.Join(linked, "skills")); err == nil {
			t.Fatal("linked parent accepted")
		}
	}
}

func TestFlatSkillDiscoveryRejectsLinkedAncestor(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".claude", "skills")
	outsideSkill := filepath.Join(home, "outside", "account", "skill")
	if err := os.MkdirAll(outsideSkill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outsideSkill, "SKILL.md"), []byte("# test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "outside"), filepath.Join(root, "synced")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	cfg, store, logger, _ := setupTestEnv(t)
	w := New(cfg, []string{root}, nil, store, logger, nil, nil)
	path := filepath.Join(root, "synced", "account", "skill")
	if events := w.pendingInstallEvents(path); len(events) != 0 {
		t.Fatalf("linked ancestor yielded install events: %+v", events)
	}
}

func TestLinkedSkillRootIsWatchedAfterItBecomesPlain(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "cursor"
	cfg.Watch.RescanEnabled = true
	cfg.AssetPolicy.Skill.Allowed = []config.AssetPolicyRule{{Name: "skill", Reason: "test policy"}}
	home := t.TempDir()
	root := filepath.Join(home, ".cursor", "skills")
	outside := filepath.Join(home, "outside")
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, root); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	admitted := make(chan AdmissionResult, 1)
	w := New(cfg, []string{root}, nil, store, logger, nil, func(result AdmissionResult) { admitted <- result })
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- w.Run(ctx) }()
	defer func() { cancel(); <-errCh }()
	deadline := time.After(5 * time.Second)
	for !w.firstCycleDone.Load() {
		select {
		case <-deadline:
			t.Fatal("watcher did not complete its first cycle")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	skill := filepath.Join(root, "skill")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("# test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-admitted:
		if result.Event.Path != skill {
			t.Fatalf("admitted %+v, want repaired root skill", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("skill in repaired root got no admission")
	}
}

func TestNestedCategoryAndSkillEventsAdmitOnce(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "hermes"
	cfg.AssetPolicy.Skill.Allowed = []config.AssetPolicyRule{{Name: "one", Reason: "test policy"}}
	root := filepath.Join(t.TempDir(), ".hermes", "skills")
	category := filepath.Join(root, "category")
	skill := filepath.Join(category, "one")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("# test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	admitted := make(chan AdmissionResult, 4)
	w := New(cfg, []string{root}, nil, store, logger, nil, func(result AdmissionResult) { admitted <- result })
	w.queuePending(category)
	w.queuePending(skill)
	w.mu.Lock()
	w.pending[category] = time.Now().Add(-2 * w.debounce)
	w.pending[skill] = time.Now().Add(-2 * w.debounce)
	w.mu.Unlock()
	w.processPending(context.Background())
	w.waitAdmissions()
	if len(admitted) != 1 {
		t.Fatalf("admissions = %d, want one", len(admitted))
	}
	if result := <-admitted; result.Event.Path != skill || result.Verdict != VerdictAllowed {
		t.Fatalf("admission = %+v", result)
	}
}
