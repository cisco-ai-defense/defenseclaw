// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// Native GAP-1557 proof: powershell.exe consumes positional -wd but runs the
// body in the hook call's original cwd (TST-16012). Each launcher must have
// the same cell as that body submitted directly from the same cwd; changing
// the requested folder cannot hide a protected cwd or invent one.
func TestGAP1557WindowsPowerShellPositionalWriteUsesOriginalCWD(t *testing.T) {
	home := filepath.Join(t.TempDir(), "fixture")
	state := filepath.Join(home, ".defenseclaw")
	keys := filepath.Join(home, ".ssh")
	project := filepath.Join(home, "project")
	for _, dir := range []string{state, keys, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(state, "config.yaml"), filepath.Join(keys, "authorized_keys"),
		filepath.Join(project, "notes.txt")} {
		if err := os.WriteFile(file, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	rows := []struct {
		name, cwd, requested, body string
		attack                     bool
	}{
		{"state-cwd", state, project, "Set-Content -Path config.yaml -Value marker", true},
		{"keys-cwd", keys, project, "Add-Content -Path authorized_keys -Value marker", true},
		{"project-cwd-state-requested", project, state, "Set-Content -Path notes.txt -Value marker", false},
	}
	for _, pack := range gap0437Packs {
		a := gap0437Server(t, pack, "codex", "action")
		for _, row := range rows {
			plain, _ := gap0198RoutePost(t, a, "codex", row.cwd, row.body, home, pack.managed)
			if row.attack && plain == "allow" {
				t.Fatalf("%s %s: direct write has no protected cell", pack.name, row.name)
			}
			for _, option := range []string{"-wd", "-WorkingDirectory"} {
				argv := []string{"powershell.exe", "-NoProfile", option, row.requested, row.body}
				got, _ := gap0198RoutePost(t, a, "codex", row.cwd, argv, home, pack.managed)
				if got != plain {
					t.Errorf("%s %s %s: launcher %s, direct write %s", pack.name, row.name, option, got, plain)
				}
			}
		}
	}
}
