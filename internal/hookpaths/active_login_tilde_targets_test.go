// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// GAP-2378: the gateway judges a ~<login> spelling of the home as the home
// (actionfacts.ActiveUserTildeTwin); a gateway behind ProtectHome reads
// that spelling's targets from this map, so the hook lists them under the
// home spelling, for a directory login (user@domain) that is the home's
// base name and for one that is not (sssd /home/%d/%u).
func TestResolveListsActiveLoginTildeTargetsUnderTheHome(t *testing.T) {
	skipPOSIXGrammarOnWindows(t)
	for _, tc := range []struct{ name, base, login, spelling string }{
		{"base name", "eng1@dclab.test", "", "~eng1@dclab.test"},
		{"base name without case", "eng1@dclab.test", "", "~ENG1@DCLAB.TEST"},
		{"login is not the base name", "eng1", "eng1@dclab.test", "~eng1@dclab.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "dclab.test", tc.base)
			cwd := filepath.Join(home, "project")
			if err := os.MkdirAll(cwd, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(cwd, "a.txt"), []byte("a"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			restore := clientLogin
			t.Cleanup(func() { clientLogin = restore })
			login := tc.login
			clientLogin = func() string { return login }
			for command, want := range map[string]string{
				"cp a.txt " + tc.spelling + "/project/b.txt":         filepath.Join(cwd, "b.txt"),
				"echo x > " + tc.spelling + "/project/notes.txt":     filepath.Join(cwd, "notes.txt"),
				"echo k >> " + tc.spelling + "/.ssh/authorized_keys": filepath.Join(home, ".ssh", "authorized_keys"),
			} {
				payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
					"tool_input": map[string]string{"command": command}})
				if err != nil {
					t.Fatal(err)
				}
				targets, ok := Decode(Resolve(payload))
				if !ok {
					t.Fatalf("%q: no evidence", command)
				}
				if _, listed := targets[want]; !listed {
					t.Errorf("%q: %s not listed (%v)", command, want, targets)
				}
			}
		})
	}
}
