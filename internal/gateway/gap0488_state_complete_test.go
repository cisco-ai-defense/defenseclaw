// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// GAP-0488, GAP-0073 (g622b round 9): a native patch target is judged against
// a complete view of the active state. A state directory the hook cannot list
// blocks a hard link to it in every profile; an ordinary hard link or link in
// the project stays allowed in balanced, as the ordinary file is. POSIX
// permissions emulate the managed gateway that cannot read the project.

//go:build !windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// g622b9PatchOutcome judges a patch of path (relative to project) as the
// managed Hermes V4A or OpenCode patch tool, in the rule pack pack.
func g622b9PatchOutcome(t *testing.T, connector, home, project, path, pack string) hermesHookOutcome {
	t.Helper()
	if connector == "hermes" {
		body := hermesPatchBody(t, project, "patch", map[string]any{"mode": "patch", "patch": hermesV4AUpdate(path)})
		return managedHermesHook(t, home, pack, body)
	}
	body := opencodeV2PatchBody(t, project, "patch", "*** Begin Patch\n*** Update File: "+path+"\n@@\n # base\n+changed\n*** End Patch\n")
	return managedOpenCodeHook(t, home, pack, body)
}

func TestG622b9UnlistableStateDirectoryBlocksNativePatches(t *testing.T) {
	for _, mode := range []os.FileMode{0, 0o111} {
		for _, connector := range []string{"hermes", "opencode"} {
			for _, pack := range []string{"", "strict"} {
				t.Run(fmt.Sprintf("%o/%s/%s", mode, connector, pack), func(t *testing.T) {
					home, project := hermesPatchHome(t)
					t.Setenv("DEFENSECLAW_HOME", t.TempDir())
					policies := filepath.Join(home, ".defenseclaw", "policies")
					if err := os.MkdirAll(policies, 0o700); err != nil {
						t.Fatal(err)
					}
					state := filepath.Join(policies, "rule.rego")
					if err := os.WriteFile(state, []byte("# base\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Link(state, filepath.Join(project, "state-alias.txt")); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(policies, mode); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Chmod(policies, 0o700) })
					if _, err := os.ReadDir(policies); err == nil {
						t.Skip("the test process can list a directory it was denied")
					}
					if got := g622b9PatchOutcome(t, connector, home, project, "state-alias.txt", pack); got.action != "block" {
						t.Errorf("hard link to a state file in an unlistable tree allowed: %s", got)
					}
				})
			}
		}
	}
}

// Links in the project that lead to no state stay allowed in balanced, for
// both patch tools: a hard link between two project files, a link to a project
// file and a link to a link, each next to a state tree the patch tool can
// read (round-8 review items 2 and 3).
func TestG622b9OrdinaryProjectLinksAllowInBalanced(t *testing.T) {
	for _, connector := range []string{"hermes", "opencode"} {
		t.Run(connector, func(t *testing.T) {
			home, project := hermesPatchHome(t)
			t.Setenv("DEFENSECLAW_HOME", t.TempDir())
			hooks := filepath.Join(home, ".defenseclaw", "hooks")
			if err := os.MkdirAll(hooks, 0o700); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 40; i++ {
				if err := os.WriteFile(filepath.Join(hooks, fmt.Sprintf("entry-%02d", i)), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			notes := filepath.Join(project, "notes.txt")
			for name, link := range map[string]func() error{
				"hard-link.txt":    func() error { return os.Link(notes, filepath.Join(project, "hard-link.txt")) },
				"soft-link.txt":    func() error { return os.Symlink(notes, filepath.Join(project, "soft-link.txt")) },
				"soft-to-soft.txt": func() error { return os.Symlink("soft-link.txt", filepath.Join(project, "soft-to-soft.txt")) },
			} {
				if err := link(); err != nil {
					t.Fatal(name, err)
				}
			}
			for _, name := range []string{"hard-link.txt", "soft-link.txt", "soft-to-soft.txt"} {
				if got := g622b9PatchOutcome(t, connector, home, project, name, ""); got.action != "allow" {
					t.Errorf("%s: ordinary project link blocked in balanced: %s", name, got)
				}
			}
		})
	}
}

// A link in the project to a state file stays blocked in balanced and strict
// whether the link is a symlink or a symlink to a hard link of the state file.
func TestG622b9LinksToStateStayBlockedForNativePatches(t *testing.T) {
	for _, connector := range []string{"hermes", "opencode"} {
		for _, pack := range []string{"", "strict"} {
			t.Run(connector+"/"+pack, func(t *testing.T) {
				home, project := hermesPatchHome(t)
				t.Setenv("DEFENSECLAW_HOME", t.TempDir())
				policies := filepath.Join(home, ".defenseclaw", "policies")
				if err := os.MkdirAll(policies, 0o700); err != nil {
					t.Fatal(err)
				}
				state := filepath.Join(policies, "rule.rego")
				if err := os.WriteFile(state, []byte("# base\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				hard := filepath.Join(project, "state-hard.txt")
				if err := os.Link(state, hard); err != nil {
					t.Fatal(err)
				}
				for name, target := range map[string]string{"state-soft.txt": state, "soft-to-hard.txt": hard} {
					if err := os.Symlink(target, filepath.Join(project, name)); err != nil {
						t.Fatal(err)
					}
				}
				for _, name := range []string{"state-hard.txt", "state-soft.txt", "soft-to-hard.txt"} {
					if got := g622b9PatchOutcome(t, connector, home, project, name, pack); got.action != "block" {
						t.Errorf("%s: link to a state file allowed: %s", name, got)
					}
				}
			})
		}
	}
}

// The strict policy tier does not trust a Hermes V4A link it cannot read
// again: an ordinary project symlink is refused there (owner steer: the
// protective rule that causes the false block moves to strict), while an
// ordinary hard link, which has no link to retarget, stays allowed.
func TestG622b9StrictTierRefusesAnUnreadableHermesLinkOnly(t *testing.T) {
	home, project := hermesPatchHome(t)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	notes := filepath.Join(project, "notes.txt")
	if err := os.Symlink(notes, filepath.Join(project, "soft-link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(notes, filepath.Join(project, "hard-link.txt")); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"soft-link.txt": "block", "hard-link.txt": "allow", "notes.txt": "allow"} {
		if got := g622b9PatchOutcome(t, "hermes", home, project, name, "strict"); got.action != want {
			t.Errorf("strict, %s: %s, want %s", name, got, want)
		}
	}
}
