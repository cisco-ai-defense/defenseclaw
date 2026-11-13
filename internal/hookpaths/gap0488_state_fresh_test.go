// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// GAP-0488, GAP-0073 (g622b round 8): a native patch target is judged by the
// identity of the file against the whole active state, read fresh, through
// the proof and the answer. These cells pin the cases a cached or bounded
// view of the state let through. POSIX permissions emulate the managed
// gateway that cannot read the project.

//go:build !windows

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestG622b8StateAddedInsideIndexTTLIsStillProtected(t *testing.T) {
	for _, connector := range []string{"hermes", "opencode"} {
		t.Run(connector, func(t *testing.T) {
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			project := filepath.Join(home, "proj")
			root := filepath.Join(home, ".defenseclaw")
			for _, dir := range []string{project, root} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			one, two := filepath.Join(project, "one.txt"), filepath.Join(project, "two.txt")
			if err := os.WriteFile(one, []byte("# base\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(one, two); err != nil {
				t.Fatal(err)
			}
			// This ordinary hard link creates a cached view of the state tree.
			if _, same := ResolveActiveStateHardlinkTarget(two, home); same {
				t.Fatal("ordinary link was state")
			}
			target := filepath.Join(project, "target.txt")
			if err := os.WriteFile(target, []byte("# base\n"), 0600); err != nil {
				t.Fatal(err)
			}
			evidence := g622bPatchEvidence(t, connector, project, target)
			watch := watchOfEvidence(evidence)
			if watch == nil || watch.Changed() {
				t.Fatal("ordinary patch target changed before swap")
			}
			state := filepath.Join(root, "policies", "new-rule.rego")
			if err := os.MkdirAll(filepath.Dir(state), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(state, []byte("# base\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(state, target); err != nil {
				t.Fatal(err)
			}
			if !watch.Changed() {
				t.Error("post-proof swap to newly added protected state file was not detected")
			}
			fresh, ok := Decode(g622bPatchEvidence(t, connector, project, target))
			if !ok || fresh[target] != state {
				t.Errorf("known protected state hard link was attested as ordinary: target=%q, want %q", fresh[target], state)
			}
		})
	}
}

// A walk that reaches its entry bound before it finds the file proves nothing:
// the target is left unresolved (the patch is not attested) and a watch
// refuses it, while a walk inside its bound still names the state file and an
// ordinary hard link stays attested as itself.
func TestG622b8BoundedStateWalkNeverAttestsAnOrdinaryTarget(t *testing.T) {
	old := activeStateExactEntries
	defer func() { activeStateExactEntries = old; resetActiveStateViews() }()
	for _, connector := range []string{"hermes", "opencode"} {
		t.Run(connector, func(t *testing.T) {
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			project := filepath.Join(home, "proj")
			root := filepath.Join(home, ".defenseclaw")
			hooks := filepath.Join(root, "hooks")
			for _, dir := range []string{project, hooks, filepath.Join(root, "policies")} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 200; i++ {
				if err := os.WriteFile(filepath.Join(hooks, fmt.Sprintf("entry-%03d", i)), []byte("x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			state := filepath.Join(root, "policies", "rule.rego")
			if err := os.WriteFile(state, []byte("# base\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			ordinary := filepath.Join(project, "ordinary.txt")
			twin := filepath.Join(project, "ordinary-twin.txt")
			protected := filepath.Join(project, "state-link.txt")
			for path, source := range map[string]string{twin: ordinary, protected: state} {
				if source == ordinary {
					if err := os.WriteFile(ordinary, []byte("x\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Link(source, path); err != nil {
					t.Fatal(err)
				}
			}
			// Inside the bound the walk names the state file, and the benign twin stays itself.
			activeStateExactEntries = old
			resetActiveStateViews()
			if got, ok := Decode(g622bPatchEvidence(t, connector, project, protected)); !ok || got[protected] != state {
				t.Errorf("state hard link = %q, want %q", got[protected], state)
			}
			if got, ok := Decode(g622bPatchEvidence(t, connector, project, twin)); !ok || got[twin] != twin || got[PatchCompleteKey] != "1" {
				t.Errorf("ordinary hard link not attested as itself: %q complete=%q", got[twin], got[PatchCompleteKey])
			}
			// Past the entry bound the answer is unknown, and unknown is never attested.
			activeStateExactEntries = 0
			resetActiveStateViews()
			for _, target := range []string{protected, twin} {
				got, ok := Decode(g622bPatchEvidence(t, connector, project, target))
				if ok && (got[PatchCompleteKey] == "1" || got[target] != "") {
					t.Errorf("target %s attested although the state walk was bounded: %q complete=%q", target, got[target], got[PatchCompleteKey])
				}
			}
			activeStateExactEntries = old
			resetActiveStateViews()
			watch := watchOfEvidence(g622bPatchEvidence(t, connector, project, ordinary))
			if watch == nil || watch.Changed() {
				t.Fatal("ordinary patch target changed before the entry bound was lowered")
			}
			activeStateExactEntries = 0
			resetActiveStateViews()
			if !watch.Changed() {
				t.Error("a multiply linked target the bounded walk could not place was not refused")
			}
		})
	}
}
