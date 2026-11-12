// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows create POSIX files and close a directory with chmod.

//go:build !windows

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// codexRolloutCall records a function call of the Codex session rollout, the
// only place the folder a shell call runs in is written (the PreToolUse hook
// sends {"command": ...} and the session folder only), and returns the hook
// call that carries it.
func codexRolloutCall(t *testing.T, home, project, workdir, command string) map[string]any {
	t.Helper()
	sessions := filepath.Join(home, ".codex", "sessions", "2026", "11", "09")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	rollout := filepath.Join(sessions, "rollout-2026-11-09T00-00-00-call.jsonl")
	arguments, _ := json.Marshal(map[string]any{"cmd": command, "workdir": workdir})
	line, _ := json.Marshal(map[string]any{"type": "response_item", "payload": map[string]any{
		"type": "function_call", "name": "exec_command", "arguments": string(arguments), "call_id": "call_relative_patch",
	}})
	if err := os.WriteFile(rollout, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	call := codexBashCall(command)(project)
	call["tool_use_id"] = "call_relative_patch"
	call["transcript_path"] = rollout
	return call
}

// A patch the Codex hook sees as a shell here-document with a RELATIVE file
// name runs in the folder the model gave the call, which the hook payload
// leaves out: the managed hook client reads it from the session rollout as
// the user, as the per-user gateway does, so a loader file named relative to
// /etc gets the verdict of the same patch with the absolute name of that file,
// in every profile and mode: the rule fires, and the action is the one the
// absolute name gets (a block in the balanced and strict profiles; the
// permissive pack alerts on this rule for the absolute name too). The same
// patch with the session folder as its folder, and an ordinary file in /etc,
// stay allowed.
func TestCodexRelativePatchIsJudgedInTheFolderTheCallRunsIn(t *testing.T) {
	const loader = "persistence.global_ld_preload_install"
	patch := func(name string) string {
		return codexHeredocPatch("Add File", name, "+/usr/local/lib/libreview.so\n")
	}
	rows := []struct {
		name, workdir, file string
		blocked             bool
	}{
		{"loader file with workdir /etc", "/etc", "ld.so.preload", true},
		{"loader file with a dot-dot workdir", "{project}/{to-root}/etc", "ld.so.preload", true},
		{"loader file with a trailing slash", "/etc/", "ld.so.preload", true},
		{"loader file in the session folder", "{project}", "ld.so.preload", false},
		{"ordinary file with workdir /etc", "/etc", "notes-review.txt", false},
		{"relative name with a folder part", "/", "etc/ld.so.preload", true},
	}
	for _, managed := range []bool{false, true} {
		for _, profile := range []string{"default", "permissive", "strict"} {
			_, absolute := postConnectorHookBehindProtectHome(t, "codex", managed, profile, func(home, project string) map[string]any {
				return codexBashCall(patch("/etc/ld.so.preload"))(project)
			})
			wantAction := hookBodyAction(absolute)
			if profile != "permissive" && wantAction != "block" {
				t.Fatalf("the absolute name is not blocked in %s: %.500s", profile, absolute)
			}
			for _, row := range rows {
				t.Run(map[bool]string{false: "per-user", true: "managed"}[managed]+"/"+profile+"/"+row.name, func(t *testing.T) {
					_, body := postConnectorHookBehindProtectHome(t, "codex", managed, profile, func(home, project string) map[string]any {
						workdir := strings.ReplaceAll(row.workdir, "{project}", project)
						workdir = strings.ReplaceAll(workdir, "{to-root}", dotDotToRoot(t, project))
						return codexRolloutCall(t, home, project, workdir, patch(row.file))
					})
					if named := strings.Contains(body, loader); named != row.blocked {
						t.Fatalf("the loader rule is named = %t, want %t: %.500s", named, row.blocked, body)
					}
					if row.blocked && hookBodyAction(body) != wantAction {
						t.Fatalf("action = %q, want %q, the action of the absolute name: %.500s", hookBodyAction(body), wantAction, body)
					}
				})
			}
		}
	}
}

// dotDotToRoot is the dot-dot path that climbs from the folder to the root as
// the operating system walks it: the count comes from the physical folder, so
// a temp dir under a link (the /var link of macOS, whose physical folder is one
// level deeper) is climbed in full, and not a fixed count short of the root.
func dotDotToRoot(t *testing.T, folder string) string {
	t.Helper()
	physical, err := filepath.EvalSymlinks(folder)
	if err != nil {
		t.Fatal(err)
	}
	up, err := filepath.Rel(physical, string(filepath.Separator))
	if err != nil {
		t.Fatal(err)
	}
	return up
}

// hookBodyAction is the action field of a hook response body.
func hookBodyAction(body string) string {
	var verdict struct {
		Action string `json:"action"`
	}
	_ = json.Unmarshal([]byte(body), &verdict)
	return verdict.Action
}
