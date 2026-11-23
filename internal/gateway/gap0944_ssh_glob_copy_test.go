// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// On Windows a glob copy out of an SSH folder the walk cannot tie to the
// active home (another account, a nested .ssh under the profile) keeps the
// block of rel in every tier of the tool-inspect route; the glob placeholder
// of GAP-0018 had left it with no reading at all (rel-1-0-10:GAP-0944).
func TestGAP0944SSHFolderGlobCopyKeepsTheRelBlockOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("rel blocks these rows on Windows only; POSIX rows are pinned by TestOwnSSHFolderCopyThroughTheHookRoute")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{".ssh", "project", "backup"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	replacer := strings.NewReplacer("{H}", home)
	for _, command := range []string{
		`cp -r {H}/.ssh/* /tmp/ssh_backup/`,
		`cp -r {H}/backup/* {H}/.ssh/`,
		`cp -r C:\Users\gap0944other\.ssh\* /tmp/ssh_backup/`,
		`cp -r C:/Users/gap0944other/.ssh/* /tmp/ssh_backup/`,
	} {
		for _, p := range gap0437Packs {
			a := gap0437Server(t, p, "openclaw", "action")
			// The first call of a fresh server builds the rule generation,
			// which on a slow Windows box can take longer than the scan
			// deadline (rel-1-0-10:GAP-0958). A harmless call takes that
			// cost before the inspect these rows pin, which keeps the
			// production deadline (rel-1-0-10:GAP-1012).
			warmDefenseClawControl(t, a.handleInspectTool, "/api/v1/inspect/tool", map[string]any{
				"tool": "exec", "connector": "openclaw", "args": map[string]any{"command": "ls", "workdir": cwd},
			})
			out := gap0437Inspect(t, a, cwd, replacer.Replace(command))
			if out["action"] != "block" {
				t.Errorf("%s %s: action %v findings %v, want block (rel)", p.name, command, out["action"], out["findings"])
			}
		}
	}
}
