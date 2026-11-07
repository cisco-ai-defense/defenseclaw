// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// GAP-0488, GAP-0073 (g622b round 8): a native patch target is judged by the
// identity of the file against the whole active state, read fresh, through
// the proof and the answer. These cells pin the cases a cached or bounded
// view of the state let through. POSIX permissions emulate the managed
// gateway that cannot read the project.

//go:build !windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A new protected policy file can appear during the identity index's TTL.
// It must still block through either native patch spelling.
func TestG622b8LateStateHardlinkBlocksNativePatches(t *testing.T) {
	for _, connector := range []string{"hermes", "opencode"} {
		for _, pack := range []string{"", "strict"} {
			t.Run(connector+"/"+pack, func(t *testing.T) {
				home, project := hermesPatchHome(t)
				t.Setenv("DEFENSECLAW_HOME", t.TempDir())
				root := filepath.Join(home, ".defenseclaw")
				if err := os.MkdirAll(root, 0700); err != nil {
					t.Fatal(err)
				}
				ordinary := filepath.Join(project, "ordinary-alias.txt")
				if err := os.Link(filepath.Join(project, "notes.txt"), ordinary); err != nil {
					t.Fatal(err)
				}
				// A normal patch target builds the shared identity index.
				if mapped, same := hookpaths.ResolveActiveStateHardlinkTarget(ordinary, home); same {
					t.Fatalf("ordinary link mapped to %s", mapped)
				}
				state := filepath.Join(root, "policies", "new-rule.rego")
				if err := os.MkdirAll(filepath.Dir(state), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(state, []byte("# base\n"), 0600); err != nil {
					t.Fatal(err)
				}
				alias := filepath.Join(project, "late-state.txt")
				if err := os.Link(state, alias); err != nil {
					t.Fatal(err)
				}
				var got hermesHookOutcome
				if connector == "hermes" {
					body := hermesPatchBody(t, project, "patch", map[string]any{"mode": "patch", "patch": hermesV4AUpdate("late-state.txt")})
					got = managedHermesHook(t, home, pack, body)
				} else {
					patch := "*** Begin Patch\n*** Update File: late-state.txt\n@@\n # base\n+changed\n*** End Patch\n"
					body := opencodeV2PatchBody(t, project, "patch", patch)
					got = managedOpenCodeHook(t, home, pack, body)
				}
				if got.action != "block" || !got.rules["tamper.detector_state_write"] {
					t.Errorf("protected policy hard link allowed after index cache was built: %s", got)
				}
			})
		}
	}
}

// Every state file must stay protected even when the active state contains
// more entries than the identity index's fixed walk bound.
func TestG622b8StateBeyondIndexBoundBlocksNativePatches(t *testing.T) {
	home, project := hermesPatchHome(t)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	root := filepath.Join(home, ".defenseclaw")
	hooks := filepath.Join(root, "hooks")
	policies := filepath.Join(root, "policies")
	for _, dir := range []string{hooks, policies} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// hooks is visited before policies; the real bound is 4,096 entries.
	for i := 0; i < 4200; i++ {
		path := filepath.Join(hooks, fmt.Sprintf("entry-%04d", i))
		if err := os.WriteFile(path, []byte("x\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	state := filepath.Join(policies, "rule.rego")
	if err := os.WriteFile(state, []byte("# base\n"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(project, "state-link.txt")
	if err := os.Link(state, alias); err != nil {
		t.Fatal(err)
	}
	for _, pack := range []string{"", "strict"} {
		hermes := hermesPatchBody(t, project, "patch", map[string]any{"mode": "patch", "patch": hermesV4AUpdate("state-link.txt")})
		if got := managedHermesHook(t, home, pack, hermes); got.action != "block" || !got.rules["tamper.detector_state_write"] {
			t.Errorf("Hermes pack %q allowed protected policy file beyond index bound: %s", pack, got)
		}
		patch := "*** Begin Patch\n*** Update File: state-link.txt\n@@\n # base\n+changed\n*** End Patch\n"
		opencode := opencodeV2PatchBody(t, project, "patch", patch)
		if got := managedOpenCodeHook(t, home, pack, opencode); got.action != "block" || !got.rules["tamper.detector_state_write"] {
			t.Errorf("OpenCode pack %q allowed protected policy file beyond index bound: %s", pack, got)
		}
	}
}
