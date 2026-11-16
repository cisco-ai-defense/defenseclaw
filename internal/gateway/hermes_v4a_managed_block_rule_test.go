// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// POSIX permissions emulate the managed gateway that cannot read the
// project of the user.

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// A managed gateway that cannot read the user home names the real rule for
// every V4A shape that reaches the keys file, as it does for write_file, so
// the block does not depend on the hook error path.
func TestManagedHermesV4AProtectedTargetNamesTheKeysRule(t *testing.T) {
	home, project := hermesPatchHome(t)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.Link(keys, filepath.Join(project, "keys-hard")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(project, "keys-soft")); err != nil {
		t.Fatal(err)
	}
	patch := func(body string) string {
		return hermesPatchBody(t, project, "patch", map[string]any{"mode": "patch", "patch": body})
	}
	add := func(path string) string {
		return "*** Begin Patch\n*** Add File: " + path + "\n+ssh-ed25519 AAAA lane\n*** End Patch\n"
	}
	move := func(source, dest string) string {
		return "*** Begin Patch\n*** Move File: " + source + " -> " + dest + "\n*** End Patch\n"
	}
	del := func(path string) string { return "*** Begin Patch\n*** Delete File: " + path + "\n*** End Patch\n" }
	for _, pack := range []string{"", "strict"} {
		for _, form := range []struct{ name, body string }{
			{"update-absolute", hermesV4AUpdate(keys)},
			{"update-tilde", hermesV4AUpdate("~/.ssh/authorized_keys")},
			{"add-absolute", add(keys)},
			{"add-tilde", add("~/.ssh/authorized_keys")},
			{"delete", del(keys)},
			{"move-onto", move("notes.txt", keys)},
			{"update-hard-link", hermesV4AUpdate("keys-hard")},
			{"update-symlink", hermesV4AUpdate("keys-soft")},
			{"ordinary-then-keys", hermesV4AUpdate("notes.txt", keys)},
		} {
			got := managedHermesHook(t, home, pack, patch(form.body))
			if got.action != "block" || !got.rules[hermesPatchAuthorizedKeysRule] {
				t.Errorf("pack %q: V4A %s = %s, want block by %s", pack, form.name, got, hermesPatchAuthorizedKeysRule)
			}
		}
		if got := managedHermesHook(t, home, pack, patch(hermesV4AUpdate("notes.txt"))); got.action != "allow" {
			t.Errorf("pack %q: ordinary V4A update = %s, want allow", pack, got)
		}
	}
}
