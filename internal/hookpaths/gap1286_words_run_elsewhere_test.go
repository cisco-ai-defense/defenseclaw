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

// TestGAP1286WordsRunElsewhereKeepTheirSpelling: the link reading leaves a
// word the shell reaches in another folder than the hook's, or on a link it
// replaces, as written (rel-1-0-10:GAP-1286, a false block of the GAP-1243
// link twin): builtin cd is cd, a function body runs where the function is
// called (after a later cd too), and install replaces its destination link
// and leaves the file it reaches alone. A source operand of install, a word
// of a function called before any change, and builtin cat still follow
// their links.
func TestGAP1286WordsRunElsewhereKeepTheirSpelling(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home", "alice")
	app := filepath.Join(home, "app")
	for _, dir := range []string{".ssh", ".claude", "app"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(home, ".ssh", "id_ed25519")
	settings := filepath.Join(home, ".claude", "settings.json")
	for _, name := range []string{key, settings} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	testSymlink(t, key, filepath.Join(app, "key-link"))
	testSymlink(t, "../.claude/settings.json", filepath.Join(app, "cfg-link"))
	physicalKey, err := filepath.EvalSymlinks(key)
	if err != nil {
		t.Fatal(err)
	}
	physicalHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	keySpelling := filepath.Join(home, strings.TrimPrefix(physicalKey, physicalHome+"/"))
	for _, tc := range []struct {
		command, want string
	}{
		// The review rows: rel allows them on the hook.
		{"builtin cd /tmp && echo x > cfg-link", ""},
		{"f() { echo x > cfg-link; }; cd /tmp; f", ""},
		{"install /tmp/x cfg-link", ""},
		// The same readings in the private-key shape.
		{"builtin cd /tmp && cat key-link", ""},
		{"f() { cat key-link; }; cd /tmp; f", ""},
		{"install -m 0600 /tmp/x key-link", ""},
		// Still placed: nothing moves these words.
		{"builtin cat key-link", "builtin cat " + keySpelling},
		{"f() { cat key-link; }; f", "f() { cat " + keySpelling + "; }; f"},
		{"install key-link /tmp/out", "install " + keySpelling + " /tmp/out"},
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
