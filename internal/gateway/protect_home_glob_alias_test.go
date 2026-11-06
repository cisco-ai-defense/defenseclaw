// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute).
	cases := map[string]string{
		"cp payload keyd*/authorized_keys":       "alert",
		"cat payload >> keyd*/authorized_keys":   "alert",
		"cp payload k*/authorized_key?":          "alert",
		"cp payload ./keyd[i]r/authorized_keys2": "alert",
		"cp src/*.txt docs/":                     "allow",
		"cp payload d*/notes.txt":                "allow",
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
			if !strings.HasPrefix(got, `{"action":"`+want+`"`) ||
				want == "alert" && !strings.Contains(got, nativeWriteAuthorizedKeysRule) {
				t.Fatalf("want %s: %.600s", want, got)
			}
		})
	}
}
