// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestNativeReadOfCredentialFilesOutsideTheActiveHomeFiveTiers: a native Read
// of a credentials file is judged by the shape of the file in any home, not only
// the active one (lead probe 2026-11-15). Through the real Claude Code hook handler
// (Codex has no native Read tool: its file reads are shell reads, and the s7-gate probe sends the same rows
// through the Codex adapter) in the five tiers, the same file in a mounted or alternate home
// (/mnt/home/<u>, /data/home/<u>, /Volumes/x/Users/<u>) must get the verdict of
// the same file in another user's ordinary home (/home/other): never a clean
// allow where that one is not. The SSH key of an alternate home was a clean
// allow in every tier.
func TestNativeReadOfCredentialFilesOutsideTheActiveHomeFiveTiers(t *testing.T) {
	files := []string{".git-credentials", ".netrc", ".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials", ".kube/config", ".docker/config.json"}
	alternates := []string{"/mnt/home/alice", "/data/home/alice", "/Volumes/data/Users/bob", "/srv/homes/carol", "/Users/other", "/root"}
	// Project folders that hold the same names stay allowed.
	projects := []string{"/work/f5proj/.aws/credentials", "/work/app/.kube/config", "/srv/data/proj/.netrc"}
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
				for _, key := range []string{"/home/other/.ssh/id_rsa", "/mnt/home/alice/.ssh/id_ed25519", "/srv/homes/carol/.ssh/id_rsa"} {
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
			for _, path := range []string{"/mnt/home/alice/.ssh/id_rsa.pub", "/mnt/home/alice/.ssh/known_hosts", "/mnt/home/alice/.ssh/config", "/mnt/home/alice/notes.txt"} {
				if got := read(path); got != "allow" {
					t.Errorf("%s %s: Read %s is %s, want allow", p.name, connector, path, got)
				}
			}
		}
	}
}
