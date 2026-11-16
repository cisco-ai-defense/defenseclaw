// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-1460: behind ProtectHome the managed gateway cannot open the user's
// project. A glob through a directory alias of ~/.ssh then looked like no
// match and the key write was allowed. The hook client resolves as the
// user; the gateway now treats a glob it cannot expand, whose last
// component can name a key, as protected-named. Ordinary globs allow.
func TestR104ProtectHomeGlobThroughDirectoryAlias(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "eng1")
	project := filepath.Join(home, "project1")
	ssh := filepath.Join(home, ".ssh")
	for _, dir := range []string{ssh, project, filepath.Join(project, "docs"), filepath.Join(project, "src")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(ssh, "authorized_keys"), filepath.Join(project, "payload"),
		filepath.Join(project, "src", "a.txt")} {
		if err := os.WriteFile(file, []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(ssh, filepath.Join(project, "keydir")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	cases := map[string]bool{
		"cp payload keyd*/authorized_keys":       true,
		"cat payload >> keyd*/authorized_keys":   true,
		"cp payload k*/authorized_key?":          true,
		"cp payload ./keyd[i]r/authorized_keys2": true,
		"cp src/*.txt docs/":                     false,
		"cp payload d*/notes.txt":                false,
	}
	for command, want := range cases {
		t.Run(command, func(t *testing.T) {
			if err := os.Chmod(homes, 0o700); err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(map[string]any{"session_id": "gap1460", "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "cwd": project,
				"tool_input": map[string]any{"command": command, "description": "Copy file"}})
			if err != nil {
				t.Fatal(err)
			}
			evidence := hookpaths.Resolve(body)
			if err := os.Chmod(homes, 0); err != nil {
				t.Fatal(err)
			}
			got := overLimitHostHookWithEvidence(t, "claudecode", home, string(body), evidence)
			if blocked := nativeWriteBlocked(t, got); blocked != want {
				t.Fatalf("blocked = %t, want %t: %.600s", blocked, want, got)
			}
		})
	}
}
