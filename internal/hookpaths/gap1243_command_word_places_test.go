// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGAP1243LocalCommandWordPlaces: the laptop places each path word of a
// shell call in its own file system, so a link operand in any position is
// spelled as the file it reaches (rel-1-0-10:GAP-1243). A word that names no
// link, a program name, a top-level folder alias and an in-place sed edit of
// a link (which replaces the link) keep their spelling.
func TestGAP1243LocalCommandWordPlaces(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home", "alice")
	app := filepath.Join(home, "app")
	for _, dir := range []string{".ssh", ".claude", "app"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(home, ".ssh", "id_ed25519")
	settings := filepath.Join(home, ".claude", "settings.json")
	for _, name := range []string{key, settings, filepath.Join(app, "README.md")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(key, filepath.Join(app, "key-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.claude/settings.json", filepath.Join(app, "cfg-link")); err != nil {
		t.Fatal(err)
	}
	physicalKey, err := filepath.EvalSymlinks(key)
	if err != nil {
		t.Fatal(err)
	}
	physicalHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	// The place is spelled in the home the call names.
	keySpelling := filepath.Join(home, strings.TrimPrefix(physicalKey, physicalHome+"/"))
	settingsSpelling := filepath.Join(home, ".claude", "settings.json")
	for _, tc := range []struct {
		command, want string
	}{
		{"command cat key-link", "command cat " + keySpelling},
		{"nice -n 5 cat key-link", "nice -n 5 cat " + keySpelling},
		{`while read l; do echo "$l"; done < key-link`, `while read l; do echo "$l"; done < ` + keySpelling},
		{"exec 3<key-link; cat <&3", "exec 3<" + keySpelling + "; cat <&3"},
		{"cat /proc/self/cwd/key-link", "cat " + keySpelling},
		{"echo x 3> cfg-link", "echo x 3> " + settingsSpelling},
		{"cp /tmp/x cfg-link", "cp /tmp/x " + settingsSpelling},
		{"sed -i --follow-symlinks s/a/b/ cfg-link", "sed -i --follow-symlinks s/a/b/ " + settingsSpelling},
		{`bash -c "cat key-link"`, `bash -c "cat ` + keySpelling + `"`},
		// No link moves these words.
		{"sed -i s/a/b/ cfg-link", ""},
		{"sed -i.bak s/a/b/ cfg-link", ""},
		{"cat README.md", ""},
		{"git status", ""},
		{"cd /proc/self/cwd && ls", ""},
		{"cat /tmp/x", ""},
	} {
		places := LocalCommandWordPlaces(tc.command, app, home, ResolveWriteTarget)
		got, changed := LinkResolvedCommand(tc.command, home, places)
		if tc.want == "" {
			if changed {
				t.Errorf("%q: respelled as %q, want no change", tc.command, got)
			}
			continue
		}
		if !changed || got != tc.want {
			t.Errorf("%q: got %q changed=%t, want %q", tc.command, got, changed, tc.want)
		}
	}
}

// TestGAP1243PrivateKeyReadBehindStaticWrappers: the private-key read proof
// reads the child a static prefix wrapper runs, as it reads the plain call,
// a link operand included (rel-1-0-10:GAP-1243). A wrapper that runs no
// reader of the key, or no child, proves nothing.
func TestGAP1243PrivateKeyReadBehindStaticWrappers(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home", "alice")
	app := filepath.Join(home, "app")
	for _, dir := range []string{".ssh", "app"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(home, ".ssh", "id_ed25519")
	if err := os.WriteFile(key, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(app, "key-link")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		command string
		read    bool
	}{
		{"nice cat ~/.ssh/id_ed25519", true},
		{"nohup cat ~/.ssh/id_ed25519", true},
		{"timeout 5 cat ~/.ssh/id_ed25519", true},
		{"command cat key-link", true},
		{"nice -n 5 nohup cat key-link", true},
		{"stdbuf -o0 head -n 1 key-link", true},
		{"nice ls ~/.ssh", false},
		{"command -v cat", false},
		{"timeout 5 echo key-link", false},
		{"nice cat README.md", false},
	} {
		if got := ActionPrivateKeyRead(tc.command, app, home); got != tc.read {
			t.Errorf("%q: ActionPrivateKeyRead = %t, want %t", tc.command, got, tc.read)
		}
	}
}
