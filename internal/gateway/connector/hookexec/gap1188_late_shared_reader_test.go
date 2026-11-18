// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestGAP1188LateSharedReaderShapes: the shared reader as the late-ordinary
// rule asks it (lateOrdinaryNoAnswerPayloadAt) reads a PermissionRequest with
// the tool and input of a PreToolUse, a leading cd chain and a relative Codex
// workdir, so the ordinary calls of those shapes may follow the outage mode;
// their protected twins stay closed. The reader the managed and Secure Client
// paths ask (OrdinaryNoAnswerPayload, ordinaryNoAnswerPayloadAt) is unchanged:
// it keeps every one of those shapes closed (rel-1-0-10 GAP-1188).
func TestGAP1188LateSharedReaderShapes(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "h")
	project := filepath.Join(home, "proj")
	sub := filepath.Join(project, "sub")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw"), sub} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, file := range []string{keys, filepath.Join(sub, "plain.txt"), filepath.Join(project, "plain.txt")} {
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(keys, filepath.Join(sub, "childlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	body := func(event, tool string, input map[string]any) []byte {
		raw, err := json.Marshal(map[string]any{"hook_event_name": event, "cwd": project, "tool_name": tool, "tool_input": input})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	bash := func(event, command string) []byte {
		return body(event, "Bash", map[string]any{"command": command})
	}
	for _, tc := range []struct {
		name string
		body []byte
		late bool // lateOrdinaryNoAnswerPayloadAt; the managed reader is false for every row but the PreToolUse echo
	}{
		{"PreToolUse echo", bash("PreToolUse", "echo hi"), true},
		{"PermissionRequest echo", bash("PermissionRequest", "echo hi"), true},
		{"PermissionRequest read of a plain file", body("PermissionRequest", "Read", map[string]any{"file_path": filepath.Join(project, "plain.txt")}), true},
		{"PermissionRequest Codex exec_command", body("PermissionRequest", "exec_command", map[string]any{"cmd": "ls -la"}), true},
		{"cd then a plain file", bash("PreToolUse", "cd sub && cat plain.txt"), true},
		{"cd to the project then go test", bash("PreToolUse", "cd "+project+" && go test ./..."), true},
		{"cd then ls after a semicolon", bash("PreToolUse", "cd sub; ls"), true},
		{"PermissionRequest cd chain", bash("PermissionRequest", "cd sub && ls"), true},
		{"Codex relative workdir", body("PreToolUse", "exec_command", map[string]any{"cmd": "cat plain.txt", "workdir": "sub"}), true},
		{"Codex shell argv with a cd chain", body("PreToolUse", "shell", map[string]any{"command": []string{"bash", "-lc", "cd sub && ls"}}), true},
		{"PermissionRequest read of the keys file", body("PermissionRequest", "Read", map[string]any{"file_path": keys}), false},
		{"PermissionRequest link to the keys file", bash("PermissionRequest", "cat keylink"), false},
		{"PermissionRequest cd then a link", bash("PermissionRequest", "cd sub && cat childlink"), false},
		{"cd into the SSH folder", bash("PreToolUse", "cd ../.ssh && cat authorized_keys"), false},
		{"cd home by tilde", bash("PreToolUse", "cd ~/.ssh && cat authorized_keys"), false},
		{"cd up to the home", bash("PreToolUse", "cd .. && cat .env"), false},
		{"cd by a variable into the state folder", bash("PreToolUse", "cd $HOME/.defenseclaw && ls"), false},
		{"cd twice, then tilde", bash("PreToolUse", "cd /x; cd ~/.aws && cat credentials"), false},
		{"cd then a link after a semicolon", bash("PreToolUse", "cd sub; cat childlink"), false},
		{"Codex relative workdir into the SSH folder", body("PreToolUse", "exec_command", map[string]any{"cmd": "cat authorized_keys", "workdir": "../.ssh"}), false},
		{"Codex relative workdir up to the home", body("PreToolUse", "exec_command", map[string]any{"cmd": "ls", "workdir": ".."}), false},
		{"Codex workdir then a link", body("PreToolUse", "exec_command", map[string]any{"cmd": "cat childlink", "workdir": "sub"}), false},
		{"PostToolUse echo", bash("PostToolUse", "echo hi"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := lateOrdinaryNoAnswerPayloadAt(home, tc.body); got != tc.late {
				t.Fatalf("late-ordinary reader = %v, want %v", got, tc.late)
			}
			legacy := tc.name == "PreToolUse echo"
			if got := ordinaryNoAnswerPayloadAt(home, tc.body); got != legacy {
				t.Fatalf("managed reader = %v, want %v (unchanged)", got, legacy)
			}
		})
	}
}
