// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-1460 review (round m loop 2): with ProtectHome hiding an ordinary
// project, the managed gateway denied `git add */*` in action mode. The
// hook client expands the pattern as the user and sends the answer; a
// proved ordinary expansion allows, an expansion through a key alias
// blocks, and evidence without the client's answer (an older hook client)
// stays closed. A simple command after cd is judged in the directory the
// client keyed its answer in, not the starting directory.
func TestR104ProtectHomeOrdinaryGlobUsesClientExpansion(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "eng1")
	project := filepath.Join(home, "project1")
	aliased := filepath.Join(home, "project2")
	keys := filepath.Join(home, ".ssh")
	for _, dir := range []string{keys, filepath.Join(project, "src", "pkg"), filepath.Join(project, "docs"),
		filepath.Join(aliased, "docs")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(keys, "authorized_keys"), filepath.Join(project, "payload"),
		filepath.Join(project, "src", "a.go"), filepath.Join(project, "src", "pkg", "b.go"),
		filepath.Join(project, "assets.txt"), filepath.Join(project, ".gitignore"),
		filepath.Join(aliased, "payload")} {
		if err := os.WriteFile(file, []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(keys, filepath.Join(aliased, "keydir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(keys, "authorized_keys"), filepath.Join(aliased, "notes")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	type row struct {
		cwd, command string
		evidence     bool
		block        bool
	}
	rows := []row{
		{project, "git add */*", true, false},
		{project, "git add src/*/*", true, false},
		{project, "git add .*", true, false},
		{project, "rm -f a*", true, false},
		{project, "cd src && git add */*", true, false},
		{project, "cd src; git add .*", true, false},
		{project, "cd src && git add a*", true, false},
		{project, "cd src && ls && git add */*", true, false},
		{project, "git add -- */* && git commit -m wip", true, false},
		{aliased, "cp payload */*", true, true},
		{aliased, "cp payload *", true, true},
		{aliased, "cp payload keyd*/authorized_keys", true, true},
		{aliased, "cd docs && cp payload ../*/authorized_keys", true, true},
		{aliased, "cd docs && cp payload ../k*/*", true, true},
		{aliased, "cd docs; cp payload ../n*", true, true},
		{project, "git add */*", false, true},
		{project, "git add .*", false, true},
	}
	for _, tc := range rows {
		name := tc.command
		if !tc.evidence {
			name += " (evidence without glob answers)"
		}
		t.Run(filepath.Base(tc.cwd)+"/"+name, func(t *testing.T) {
			if err := os.Chmod(homes, 0o700); err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(map[string]any{"session_id": "gap1460-review", "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "cwd": tc.cwd,
				"tool_input": map[string]any{"command": tc.command, "description": "Stage files"}})
			if err != nil {
				t.Fatal(err)
			}
			evidence := hookpaths.Resolve(body)
			if !tc.evidence {
				evidence = withoutGlobFacts(t, evidence)
			}
			if err := os.Chmod(homes, 0); err != nil {
				t.Fatal(err)
			}
			got := overLimitHostHookWithEvidence(t, "claudecode", home, string(body), evidence)
			if blocked := nativeWriteBlocked(t, got); blocked != tc.block {
				t.Fatalf("blocked = %t, want %t: %.600s", blocked, tc.block, got)
			}
		})
	}
}

// withoutGlobFacts is the evidence an older hook client sends: the same map
// with no hookpaths.GlobFactPrefix answer.
func withoutGlobFacts(t *testing.T, evidence string) string {
	t.Helper()
	targets, ok := hookpaths.Decode(evidence)
	if !ok {
		t.Fatal("client evidence does not decode")
	}
	for key := range targets {
		if strings.HasPrefix(key, hookpaths.GlobFactPrefix) {
			delete(targets, key)
		}
	}
	encoded, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}
