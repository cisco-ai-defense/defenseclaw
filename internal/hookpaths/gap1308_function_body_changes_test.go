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

// TestGAP1308FunctionBodyWordsCountChangesBeforeTheCall: a word in a function
// body runs when the function is first called, so only a change that can run
// before it moves it: a statement before the call (after the body), or one
// earlier in the body (rel-1-0-10:GAP-1308, a regression of the GAP-1286
// fix, which counted every change of the command). The word's own cp and a
// cd after the first call leave it in the project, so the link reading
// follows its link, as for the plain call; a cd before the call (GAP-1286)
// still leaves it as written.
func TestGAP1308FunctionBodyWordsCountChangesBeforeTheCall(t *testing.T) {
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
	for _, tc := range []struct {
		command string
		follows bool
	}{
		// The review rows: 880a799368 followed the link, 78088dd913 did not.
		{"f() { cp /tmp/x cfg-link; }; f", true},
		{"f() { echo x > cfg-link; }; f; cd /tmp", true},
		{"function f { echo x > cfg-link; }; f; cd /tmp", true},
		{"f() { cat key-link; }; f; cd /tmp", true},
		// The first call runs in the project.
		{"f() { echo x > cfg-link; }; f; cd /tmp; f", true},
		// No call by name: a dynamic program may run it.
		{`f() { cp /tmp/x cfg-link; }; "$g"`, true},
		// GAP-1286: the call comes after the cd.
		{"f() { echo x > cfg-link; }; cd /tmp; f", false},
		{"f() { cat key-link; }; cd /tmp; f", false},
		{"f() { cd /tmp; cat key-link; }; f", false},
		// A call inside g runs when g is called.
		{"f() { echo x > cfg-link; }; g() { f; }; cd /tmp; g", false},
	} {
		places := LocalCommandWordPlaces(tc.command, app, home, ResolveWriteTarget)
		got, changed := LinkResolvedCommand(tc.command, home, places)
		follows := changed && (strings.Contains(got, ".claude/settings.json") || strings.Contains(got, ".ssh/id_ed25519"))
		if follows != tc.follows {
			t.Errorf("%q: got %q changed=%t, want the link followed=%t", tc.command, got, changed, tc.follows)
		}
	}
}
