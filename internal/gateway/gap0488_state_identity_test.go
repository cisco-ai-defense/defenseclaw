// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// POSIX permissions emulate the managed gateway that cannot read the
// user's project.

//go:build !windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// g622bStateFile makes one file of the active DefenseClaw state, below the
// state tree when name is a protected tree, and returns its path.
func g622bStateFile(t *testing.T, home, name string) string {
	t.Helper()
	relative := name
	switch name {
	case "cache", "hooks", "installer", "policies", "quarantine", "receipts", "registries":
		relative = filepath.Join(name, "state.dat")
	case "previous":
		relative = filepath.Join(name, "installer", "state.dat")
	}
	path := filepath.Join(home, ".defenseclaw", relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("# base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// GAP-0488, GAP-0073: a native patch target is judged by the file it is, not
// by its name. For every file the active DefenseClaw state holds, a project
// hard link and a project symlink to it block in every profile as the state
// path itself does, for Hermes V4A and for the OpenCode native patch. The
// ordinary twin (a hard link between two project files) is allowed.
func TestG622bEveryActiveStateFileIsProtectedUnderAnyNameForNativePatches(t *testing.T) {
	home, project := hermesPatchHome(t)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	ordinary := filepath.Join(project, "notes.txt")
	if err := os.Link(ordinary, filepath.Join(project, "notes-link.txt")); err != nil {
		t.Fatal(err)
	}
	type target struct{ name, state string }
	var states []target
	for _, name := range activeDefenseClawStateNames {
		states = append(states, target{name, g622bStateFile(t, home, name)})
	}
	hermes := func(target string) string {
		return hermesPatchBody(t, project, "patch", map[string]any{"mode": "patch", "patch": hermesV4AUpdate(target)})
	}
	opencode := func(target string) string {
		return opencodeV2PatchBody(t, project, "patch",
			"*** Begin Patch\n*** Update File: "+target+"\n@@\n # base\n+changed\n*** End Patch\n")
	}
	connectors := []struct {
		name  string
		body  func(string) string
		judge func(*testing.T, string, string, string) hermesHookOutcome
	}{
		{"hermes v4a", hermes, managedHermesHook},
		{"opencode patch", opencode, managedOpenCodeHook},
	}
	for _, pack := range []string{"", "strict"} {
		for _, c := range connectors {
			if got := c.judge(t, home, pack, c.body("notes-link.txt")); got.action != "allow" {
				t.Errorf("pack %q %s: hard link between two project files = %s, want allow", pack, c.name, got)
			}
			for _, s := range states {
				if got := c.judge(t, home, pack, c.body(s.state)); got.action != "block" {
					t.Errorf("pack %q %s: state path %s = %s, want block", pack, c.name, s.name, got)
				}
			}
		}
	}
	for i, s := range states {
		hard := filepath.Join(project, fmt.Sprintf("hard-%d-%s", i, filepath.Base(s.state)))
		soft := filepath.Join(project, fmt.Sprintf("soft-%d-%s", i, filepath.Base(s.state)))
		if err := os.Link(s.state, hard); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(s.state, soft); err != nil {
			t.Fatal(err)
		}
		for _, pack := range []string{"", "strict"} {
			for _, c := range connectors {
				if got := c.judge(t, home, pack, c.body(filepath.Base(hard))); got.action != "block" || !got.rules["tamper.detector_state_write"] {
					t.Errorf("pack %q %s: hard link to state %s = %s, want block by the state rule", pack, c.name, s.name, got)
				}
				if got := c.judge(t, home, pack, c.body(filepath.Base(soft))); got.action != "block" {
					t.Errorf("pack %q %s: symlink to state %s = %s, want block", pack, c.name, s.name, got)
				}
			}
		}
		if err := os.Remove(hard); err != nil {
			t.Fatal(err)
		}
	}
}
