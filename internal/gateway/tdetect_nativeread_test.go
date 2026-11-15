// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"testing"
)

// TestNativeReadOfCredentialFilesOutsideTheActiveHomeFiveTiers: a native Read
// of a credentials file is judged by the shape of the file in any account home,
// not only the active one (lead probe 2026-11-15). Through the real Claude Code
// hook handler (Codex has no native Read tool: its file reads are shell reads,
// and the s7-gate probe sends the same rows through the Codex adapter) in the
// five tiers, the same file in another account's home (/home/<u>, /Users/<u>,
// /root, <drive>:/Users/<u>, found by position and never by a folder name deeper
// in the path: rel-1-0-10:GAP-0836) must get the verdict of the same file in
// /home/other. A folder that only is called home, homes or users is a project
// folder: its files keep the verdict they had on rel.
func TestNativeReadOfCredentialFilesOutsideTheActiveHomeFiveTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home spellings (/home, /Users, /root) are read by the host's own path rules on native Windows; the C:\\Users forms are pinned by TestAccountHomeByPosition and TestOtherHomeCredentialFileShapes")
	}
	files := []string{".git-credentials", ".netrc", ".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials", ".kube/config", ".docker/config.json"}
	alternates := []string{"/home/carol", "/Users/other", "/root"}
	// Project folders that hold the same names stay allowed.
	projects := []string{"/work/f5proj/.aws/credentials", "/work/app/.kube/config", "/srv/data/proj/.netrc",
		"/work/repo/users/bob/.aws/credentials", "/srv/app/homes/x/.kube/config"}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		for _, connector := range []string{"claudecode"} {
			read := func(path string) string {
				t.Helper()
				out := gap0437Serve(t, a.handleAgentHook(connector), "/api/v1/"+map[string]string{"claudecode": "claude-code", "codex": "codex"}[connector]+"/hook", map[string]any{
					"hook_event_name": "PreToolUse", "session_id": "td-nr-" + p.name, "cwd": t.TempDir(),
					"tool_name": "Read", "tool_use_id": "tu-td-nr-" + path, "tool_input": map[string]any{"file_path": path},
				})
				action, _ := out["action"].(string)
				return action
			}
			// A proven content read of another user's SSH key keeps the verdict
			// of the active home's: a block in the strict packs.
			if p.pack == "strict" {
				for _, key := range []string{"/home/other/.ssh/id_rsa", "/Users/other/.ssh/id_ed25519", "/root/.ssh/id_rsa"} {
					if got := read(key); got != "block" {
						t.Errorf("%s %s: Read %s is %s, want block", p.name, connector, key, got)
					}
				}
			}
			for _, file := range files {
				oracle := read("/home/other/" + file)
				for _, home := range alternates {
					if got := read(home + "/" + file); got != oracle {
						t.Errorf("%s %s: Read %s/%s is %s, want %s like /home/other", p.name, connector, home, file, got, oracle)
					}
				}
			}
			for _, path := range projects {
				if got := read(path); got != "allow" {
					t.Errorf("%s %s: Read %s is %s, want allow (a project folder)", p.name, connector, path, got)
				}
			}
			// Not credentials: the same names in an alternate home stay allowed.
			for _, path := range []string{"/home/carol/.ssh/id_rsa.pub", "/home/carol/.ssh/known_hosts", "/home/carol/.ssh/config", "/home/carol/notes.txt"} {
				if got := read(path); got != "allow" {
					t.Errorf("%s %s: Read %s is %s, want allow", p.name, connector, path, got)
				}
			}
		}
	}
}
