// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"runtime"
	"testing"
)

// TestOwnDeveloperTokenReadIsJudgedLikeOwnCloudCredentialsFiveTiers
// (rel-1-0-10:GAP-0888): a read of the active account's own .git-credentials,
// .netrc or .pgpass gets the verdict rel gives it, the tier of a read of the
// account's own AWS or kube credentials, in every pack, on the Claude Code
// hook and on /inspect/tool, for a shell read (cat, sudo cat, base64) and a
// native Read. The stronger-finding replacement of the native lane is for
// another account's home (GAP-0835); it must not raise one's own files to
// CRITICAL or make the managed default pack block them. The strict packs block
// the read of each (substrate-1:GAP-0706, owner ruling 2026-11-19), at HIGH,
// never CRITICAL.
func TestOwnDeveloperTokenReadIsJudgedLikeOwnCloudCredentialsFiveTiers(t *testing.T) {
	// The account's own home is spelled the way the host spells it: a POSIX
	// path on Linux and macOS, a drive path (slash form, as an agent
	// writes it in a command) on Windows.
	home := "/home/alice"
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		home = "C:/Users/alice"
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", `C:\Users\alice`)
	}
	// The install window reads DEFENSECLAW_HOME, else HOME/.defenseclaw. Keep it in a
	// private folder: on a host with a real, unreadable /home/alice the lock read
	// fails, counts as held and the strict tier blocks.
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	cwd := home + "/proj"
	files := []struct{ kind, relative string }{
		{"aws", ".aws/credentials"},
		{"kube", ".kube/config"},
		{"git", ".git-credentials"},
		{"netrc", ".netrc"},
		{"pgpass", ".pgpass"},
	}
	type verdict struct{ action, severity string }
	read := func(out map[string]any) verdict {
		action, _ := out["action"].(string)
		severity, _ := out["severity"].(string)
		return verdict{action, severity}
	}
	for _, p := range gap0437Packs {
		got := map[string]verdict{}
		hook := gap0437Server(t, p, "claudecode", "action")
		for _, f := range files {
			target := home + "/" + f.relative
			got["hook-bash:"+f.kind] = read(gap0437Hook(t, hook, cwd, "gap0888-"+p.name+f.kind, "cat "+target))
			got["hook-sudo:"+f.kind] = read(gap0437Hook(t, hook, cwd, "gap0888-sudo-"+p.name+f.kind, "sudo cat "+target))
			got["hook-b64:"+f.kind] = read(gap0437Hook(t, hook, cwd, "gap0888-b64-"+p.name+f.kind, "base64 "+target))
			got["hook-read:"+f.kind] = read(gap0437Serve(t, hook.handleAgentHook("claudecode"), "/api/v1/claude-code/hook", map[string]any{
				"hook_event_name": "PreToolUse", "session_id": "gap0888-read-" + p.name + f.kind, "cwd": cwd,
				"tool_name": "Read", "tool_use_id": "tu-gap0888-" + p.name + f.kind, "tool_input": map[string]any{"file_path": target},
			}))
		}
		inspect := gap0437Server(t, p, "openclaw", "action")
		for _, f := range files {
			target := home + "/" + f.relative
			got["inspect-exec:"+f.kind] = read(gap0437Inspect(t, inspect, cwd, "cat "+target))
			got["inspect-read:"+f.kind] = read(gap0437Serve(t, inspect.handleInspectTool, "/api/v1/inspect/tool", map[string]any{
				"tool": "read", "connector": "openclaw", "args": map[string]any{"path": target},
			}))
		}
		for _, route := range []string{"hook-bash", "hook-sudo", "hook-b64", "hook-read", "inspect-exec", "inspect-read"} {
			aws := got[route+":aws"]
			where := func(kind string) string { return fmt.Sprintf("%s %s %s", p.name, route, kind) }
			if p.pack == "strict" && (aws.severity == "CRITICAL" || aws.action != "block") {
				t.Errorf("%s: %+v, want the strict block of an own credentials read, not CRITICAL", where("aws"), aws)
			}
			if p.pack != "strict" && (aws.severity == "CRITICAL" || aws.action == "block") {
				t.Errorf("%s: %+v, want the alert tier of an own credentials read", where("aws"), aws)
			}
			if kube := got[route+":kube"]; kube != aws {
				t.Errorf("%s: %+v, want the aws verdict %+v", where("kube"), kube, aws)
			}
			for _, kind := range []string{"git", "netrc"} {
				if v := got[route+":"+kind]; v != aws {
					t.Errorf("%s: %+v, want the aws verdict %+v", where(kind), v, aws)
				}
			}
			// .pgpass carries the user credential-store rule too, at HIGH:
			// rel alerts in the default, permissive and managed default
			// packs, and the strict packs block it.
			pg := got[route+":pgpass"]
			if pg.severity == "CRITICAL" {
				t.Errorf("%s: %+v, want no CRITICAL for an own .pgpass read", where("pgpass"), pg)
			}
			if pg.action == "block" && p.pack != "strict" {
				t.Errorf("%s: %+v, want no block outside the strict packs", where("pgpass"), pg)
			}
		}
	}
}
