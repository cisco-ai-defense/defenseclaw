// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// claudeHookLauncher is how Claude Code starts a managed hook: a shell, a
// direct child of the agent, that execs the hook in the same pid.
const claudeHookLauncher = `/bin/sh -c "'/opt/defenseclaw/bin/defenseclaw-hook' hook --connector claudecode --enterprise-managed"`

// hookLaunch is the exec of a launcher shell, its exec into the hook (the
// same pid, Tetragon names the shell as the parent) and the hook's exit.
func hookLaunch(pid int, at time.Time) []plane.Event {
	sh, hook := "sh-"+strconv.Itoa(pid), "hook-"+strconv.Itoa(pid)
	return []plane.Event{
		{Kind: plane.KindExec, PID: pid, PPID: 1400, Name: "sh", Exe: "/bin/sh", Cmdline: claudeHookLauncher,
			ExecID: sh, ParentExecID: "root", UID: uidp(1001), At: at},
		{Kind: plane.KindExec, PID: pid, PPID: pid, Name: "defenseclaw-hook", Exe: "/opt/defenseclaw/bin/defenseclaw-hook",
			Cmdline: "/opt/defenseclaw/bin/defenseclaw-hook hook --connector claudecode --enterprise-managed",
			Hook:    plane.HookVerified, ExecID: hook, ParentExecID: sh, UID: uidp(1001), At: at.Add(3 * time.Millisecond)},
		{Kind: plane.KindExit, PID: pid, ExecID: hook, Hook: plane.HookVerified, At: at.Add(250 * time.Millisecond)},
	}
}

// GAP-0023, as tg2 showed it: a Bash call that waits for approval sends
// PreToolUse, then PermissionRequest and, while the prompt waits, a
// Notification. Each hook starts from a shell that is a direct child of
// Claude; the PermissionRequest hook's shell starts about 60 ms after the
// PreToolUse decision and took it by agent and time, so the tool's own shell,
// 11 s later, found the decision used: hook_seen=false on every event of an
// approved call, exact command match or not.
func TestHookJoinSurvivesTheHookLaunchersOfAPrompt(t *testing.T) {
	t.Parallel()
	for name, command := range map[string]string{
		// The temporal join: the forwarded shell does not hash like the
		// decision's command (Python's quotes inside Claude's eval).
		"temporal": `python3 -c "import socket;s=socket.create_connection(('api.example.invalid',443))"`,
		"exact":    "cat /home/dev/tg2work/dccert-block-marker",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			base := time.Unix(1_760_000_000, 0)
			approved := base.Add(11500 * time.Millisecond)
			script := []plane.Event{{Kind: plane.KindExec, PID: 1400, PPID: 1300, Name: "claude", Exe: "/home/dev/.local/bin/claude",
				ExecID: "root", UID: uidp(1001), At: base.Add(-time.Hour)}}
			script = append(script, hookLaunch(1401, base.Add(-250*time.Millisecond))...) // PreToolUse
			script = append(script, hookLaunch(1402, base.Add(60*time.Millisecond))...)   // PermissionRequest
			script = append(script, hookLaunch(1403, base.Add(6*time.Second))...)         // Notification
			script = append(script,
				plane.Event{Kind: plane.KindExec, PID: 1404, PPID: 1400, Name: "2.1.293", Exe: claudeExe,
					Cmdline: claudeExe + " --no-config --files --follow --hidden --glob !.git", ExecID: "index", ParentExecID: "root",
					UID: uidp(1001), At: approved},
				plane.Event{Kind: plane.KindExec, PID: 1405, PPID: 1400, Name: "bash", Exe: "/bin/bash", Cmdline: claudeToolShell(command),
					ExecID: "tool", ParentExecID: "root", UID: uidp(1001), At: approved.Add(8 * time.Millisecond)},
				plane.Event{Kind: plane.KindExec, PID: 1406, PPID: 1405, Name: "python3", Exe: "/bin/python3", Cmdline: "/bin/python3 -c",
					ExecID: "child", ParentExecID: "tool", UID: uidp(1001), At: approved.Add(13 * time.Millisecond)},
				plane.Event{Kind: plane.KindPolicyEvent, PolicyOwner: plane.PolicyOwnerCustomer, Policy: "dc-tg2-net-connect",
					PID: 1406, ExecID: "child", Name: "python3", UID: uidp(1001), At: approved.Add(20 * time.Millisecond)},
			)
			host := newHost(newFake(fullCoverage(), script...))
			host.hooks = newHookRing(hookRingSize, hookRingWindow)
			host.hooks.record(HookDecision{
				Connector: "claudecode", SessionID: "sess-1", ToolInvocationID: "approved-tool",
				CommandHash: HookCommandHash(command), PeerPID: 1401, PeerUID: 1001, At: base, Action: "allow",
			})
			drainAll(t, host, len(script))
			if len(host.customer.recent) != 1 {
				t.Fatalf("customer records = %+v", host.customer.recent)
			}
			join := host.customer.recent[0].Hook
			want := HookJoinTemporal
			if name == "exact" {
				want = HookJoinExact
			}
			if join == nil || !join.Seen || join.ToolInvocationID != "approved-tool" || join.Confidence != want {
				t.Fatalf("approved call join = %+v, want %s approved-tool", join, want)
			}
		})
	}
}

func TestIsHookLauncherIgnoresQuotes(t *testing.T) {
	t.Parallel()
	for _, cmdline := range []string{
		claudeHookLauncher,
		"/bin/sh -c /opt/defenseclaw/bin/defenseclaw-hook hook --connector codex",
		`/bin/bash -c "\"/opt/defenseclaw/bin/defenseclaw-hook\" hook --connector copilot"`,
		"/bin/sh /home/dev/.defenseclaw/hooks/claude-code-hook.sh",
	} {
		if !isHookLauncher(cmdline) {
			t.Errorf("%q is a hook launcher", cmdline)
		}
	}
	for _, cmdline := range []string{claudeToolShell("cat notes.txt"), "/usr/bin/git ls-files", "/bin/sh -c 'echo defenseclaw-hookup'"} {
		if isHookLauncher(cmdline) {
			t.Errorf("%q is not a hook launcher", cmdline)
		}
	}
}
