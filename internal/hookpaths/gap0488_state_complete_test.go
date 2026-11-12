// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// GAP-0488, GAP-0073 (g622b round 9): the identity walk of the active state
// is complete or it proves nothing. A directory it cannot list makes the view
// partial (never a quiet "no match"); a large state tree is still walked to
// the end, so an ordinary target is proved ordinary; a link to a directory
// inside the state is part of the state. POSIX permissions emulate the
// unreadable state.

//go:build !windows

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// g622b9State is a home with a project, one policy file and, in the project,
// a hard link to it and a hard link between two ordinary files.
type g622b9State struct {
	home, project, root, policies, state, alias, ordinary, twin string
}

func newG622b9State(t *testing.T) g622b9State {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	s := g622b9State{home: home, project: filepath.Join(home, "proj"), root: filepath.Join(home, ".defenseclaw")}
	s.policies = filepath.Join(s.root, "policies")
	for _, dir := range []string{s.project, s.policies} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	s.state = filepath.Join(s.policies, "rule.rego")
	s.alias = filepath.Join(s.project, "state-alias.txt")
	s.ordinary = filepath.Join(s.project, "ordinary.txt")
	s.twin = filepath.Join(s.project, "ordinary-twin.txt")
	if err := os.WriteFile(s.state, []byte("# base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.ordinary, []byte("# base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for link, source := range map[string]string{s.alias: s.state, s.twin: s.ordinary} {
		if err := os.Link(source, link); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// A state directory the walk cannot list leaves part of the state unknown:
// the protected hard link is not "ordinary", and neither is its ordinary twin
// proved. Neither is attested in the evidence the hook sends, so the gateway
// blocks the patch as unproven (item 1 of the round-8 review). Readable
// again, the walk names the state file and the twin is proved ordinary.
func TestG622b9UnlistableStateDirectoryIsNeverProvedOrdinary(t *testing.T) {
	for _, mode := range []os.FileMode{0, 0o111} {
		for _, depth := range []string{"tree", "subdirectory"} {
			t.Run(fmt.Sprintf("%o/%s", mode, depth), func(t *testing.T) {
				s := newG622b9State(t)
				locked := s.policies
				if depth == "subdirectory" {
					locked = filepath.Join(s.policies, "nested")
					if err := os.MkdirAll(locked, 0o700); err != nil {
						t.Fatal(err)
					}
					nested := filepath.Join(locked, "rule.rego")
					if err := os.Rename(s.state, nested); err != nil {
						t.Fatal(err)
					}
					s.state = nested
				}
				if err := os.Chmod(locked, mode); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
				if _, err := os.ReadDir(locked); err == nil {
					t.Skip("the test process can list a directory it was denied")
				}
				for _, target := range []string{s.alias, s.twin} {
					if _, same, complete := ResolveActiveStateIdentity(target, s.home); same || complete {
						t.Errorf("%s: same=%v complete=%v, want the unknown answer (not same, not complete)", filepath.Base(target), same, complete)
					}
					for _, connector := range []string{"hermes", "opencode"} {
						got, ok := Decode(g622bPatchEvidence(t, connector, s.project, target))
						if ok && (got[PatchCompleteKey] == "1" || got[target] != "") {
							t.Errorf("%s %s attested although the state could not be read: %q complete=%q", connector, filepath.Base(target), got[target], got[PatchCompleteKey])
						}
					}
				}
				if err := os.Chmod(locked, 0o700); err != nil {
					t.Fatal(err)
				}
				if got, same, complete := ResolveActiveStateIdentity(s.alias, s.home); !same || !complete || got != filepath.Join(s.home, ".defenseclaw", "policies", mustRel(t, s.policies, s.state)) {
					t.Errorf("readable again: alias = %q same=%v complete=%v", got, same, complete)
				}
				if _, same, complete := ResolveActiveStateIdentity(s.twin, s.home); same || !complete {
					t.Errorf("readable again: ordinary twin same=%v complete=%v, want ordinary and proved", same, complete)
				}
			})
		}
	}
}

func mustRel(t *testing.T, base, target string) string {
	t.Helper()
	relative, err := filepath.Rel(base, target)
	if err != nil {
		t.Fatal(err)
	}
	return relative
}

// A state tree past the old 65,536-entry bound is walked to the end: an
// ordinary hard link between project files is proved ordinary and attested as
// itself (balanced allows it), and a state file visited after the large tree
// is still named (item 2 of the round-8 review).
func TestG622b9LargeStateTreeStillProvesAnOrdinaryTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("creates 66,000 directory entries")
	}
	s := newG622b9State(t)
	hooks := filepath.Join(s.root, "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	// Hard links of 66 seed files: far cheaper to create than 66,000 files,
	// and below the link limit of each seed.
	for seed := 0; seed < 66; seed++ {
		first := filepath.Join(hooks, fmt.Sprintf("seed-%02d", seed))
		if err := os.WriteFile(first, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 999; i++ {
			if err := os.Link(first, filepath.Join(hooks, fmt.Sprintf("entry-%02d-%03d", seed, i))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, same, complete := ResolveActiveStateIdentity(s.twin, s.home); same || !complete {
		t.Errorf("ordinary twin: same=%v complete=%v, want ordinary and proved", same, complete)
	}
	if got, same, complete := ResolveActiveStateIdentity(s.alias, s.home); !same || !complete || got != s.state {
		t.Errorf("state alias: %q same=%v complete=%v, want %q", got, same, complete, s.state)
	}
	for _, connector := range []string{"hermes", "opencode"} {
		got, ok := Decode(g622bPatchEvidence(t, connector, s.project, s.twin))
		if !ok || got[s.twin] != s.twin || got[PatchCompleteKey] != "1" {
			t.Errorf("%s: ordinary hard link not attested as itself: %q complete=%q", connector, got[s.twin], got[PatchCompleteKey])
		}
	}
}

// A link to a directory inside the state leads to files of the state, and a
// link loop in it ends the walk instead of running it.
func TestG622b9LinkedStateDirectoryIsWalked(t *testing.T) {
	s := newG622b9State(t)
	outside := filepath.Join(s.home, "elsewhere")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(outside, "moved.rego")
	if err := os.WriteFile(moved, []byte("# base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(s.policies, "extra")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(s.policies, filepath.Join(outside, "loop")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(s.project, "moved-alias.txt")
	if err := os.Link(moved, link); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(s.root, "policies", "extra", "moved.rego")
	if got, same, complete := ResolveActiveStateIdentity(link, s.home); !same || !complete || got != want {
		t.Errorf("file below a linked state directory: %q same=%v complete=%v, want %q", got, same, complete, want)
	}
	if _, same, complete := ResolveActiveStateIdentity(s.twin, s.home); same || !complete {
		t.Errorf("ordinary twin beside a link loop: same=%v complete=%v, want ordinary and proved", same, complete)
	}
}

// resetActiveStateViews forgets the kept views, so a test reads the state
// from the disk.
func resetActiveStateViews() {
	activeStateViews.Lock()
	activeStateViews.byRoot = nil
	activeStateViews.Unlock()
}

// The kept view of a settled state is used again, and is read again the
// moment a directory of the state, or a link in it, changes: a hard link
// made to the target, a file renamed in, a link made, a new state directory,
// with the directory time set back or not, and while the state is still too
// new to trust a kept view (the guard).
func TestG622b9KeptViewIsReadAgainWhenTheStateChanges(t *testing.T) {
	kept := func(s g622b9State) bool {
		activeStateViews.Lock()
		defer activeStateViews.Unlock()
		_, ok := activeStateViews.byRoot[s.root]
		return ok
	}
	changes := map[string]func(t *testing.T, s g622b9State, extra string){
		"hard-link-into-state": func(t *testing.T, s g622b9State, extra string) {
			mustDo(t, os.Link(extra, filepath.Join(s.policies, "added.rego")))
		},
		"rename-other-link-into-state": func(t *testing.T, s g622b9State, extra string) {
			mustDo(t, os.Rename(extra+".twin", filepath.Join(s.policies, "moved.rego")))
		},
		"symlink-into-state": func(t *testing.T, s g622b9State, extra string) {
			mustDo(t, os.Symlink(extra, filepath.Join(s.policies, "link.rego")))
		},
		"new-state-directory": func(t *testing.T, s g622b9State, extra string) {
			mustDo(t, os.MkdirAll(filepath.Join(s.root, "hooks"), 0o700))
			mustDo(t, os.Link(extra, filepath.Join(s.root, "hooks", "hook.sh")))
		},
	}
	for name, change := range changes {
		for _, setBack := range []bool{false, true} {
			for _, settled := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/setback=%v/settled=%v", name, setBack, settled), func(t *testing.T) {
					s := newG622b9State(t)
					extra := filepath.Join(s.project, "extra.txt")
					mustDo(t, os.WriteFile(extra, []byte("# base\n"), 0o600))
					mustDo(t, os.Link(extra, extra+".twin"))
					time.Sleep(2 * activeStateViewGuard)
					resetActiveStateViews()
					if _, same, complete := ResolveActiveStateIdentity(extra, s.home); same || !complete {
						t.Fatalf("before: same=%v complete=%v", same, complete)
					}
					if !kept(s) {
						t.Fatal("a settled state was not kept")
					}
					if !settled {
						youngStateViewIsNotKept(t, s, extra, kept)
					}
					change(t, s, extra)
					if setBack {
						old := time.Now().Add(-time.Hour)
						for _, dir := range []string{s.policies, s.root, filepath.Join(s.root, "hooks")} {
							_ = os.Chtimes(dir, old, old)
						}
					}
					if _, same, complete := ResolveActiveStateIdentity(extra, s.home); !same || !complete {
						t.Errorf("after the change: same=%v complete=%v, want the target found in the state", same, complete)
					}
				})
			}
		}
	}
}

// youngStateViewIsNotKept changes the policies directory and reads at once.
// Where the guard is a fixed time (activeStateViewGuard) the view of that
// state is never kept. Where it is the filesystem clock tick, the view is not
// kept unless the write fell in an earlier tick than the read, which the
// stamp of the directory shows: a kept view then has every stamp older than
// the clock, and some of a few tries read in the tick of the write.
func youngStateViewIsNotKept(t *testing.T, s g622b9State, extra string, kept func(g622b9State) bool) {
	t.Helper()
	_, tickClock := filesystemClockNow()
	notKept := 0
	for try := 0; try < 40; try++ {
		resetActiveStateViews()
		mustDo(t, os.WriteFile(filepath.Join(s.policies, fmt.Sprintf("fresh-%d.rego", try)), nil, 0o600))
		ResolveActiveStateIdentity(extra, s.home)
		if !kept(s) {
			notKept++
			if !tickClock {
				return
			}
			continue
		}
		if !tickClock {
			t.Fatal("a view of a state changed inside the guard was kept")
		}
		info, err := os.Stat(s.policies)
		if err != nil {
			t.Fatal(err)
		}
		changed, _ := statChangeTime(info)
		if now, _ := filesystemClockNow(); !changed.Before(now) {
			t.Fatalf("a view was kept with a stamp %v not older than the filesystem clock %v", changed, now)
		}
	}
	if notKept == 0 {
		t.Fatal("a view of a state changed a moment ago was always kept")
	}
}

func mustDo(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
