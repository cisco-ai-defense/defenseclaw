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
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// Claude Code's own shells before the first Bash call of a session, as
// Tetragon forwarded them on tg2 (Claude Code 2.1.294).
const (
	claudeEnvShell      = "/bin/bash -c env"
	claudeSnapshotShell = `/bin/bash -c -l "SNAPSHOT_FILE=/home/dev/.claude/shell-snapshots/snapshot-bash-1.sh source /home/dev/.bashrc < /dev/null"`
)

// GAP-0023, the first call of a session: after the PreToolUse decision Claude
// starts bash -c env and the snapshot writer, both direct children of the
// agent, about 100 ms before the tool's own shell. The first took the
// decision by agent and time and the tool's shell found it used:
// hook_seen=false on the first call of every session, prompted or not.
func TestHookJoinSkipsClaudesFirstCallSetupShells(t *testing.T) {
	t.Parallel()
	for name, command := range map[string]string{
		"temporal": `python3 -c "import socket;s=socket.create_connection(('api.example.invalid',443))"`,
		"exact":    "curl -s https://api.example.invalid/",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			base := time.Unix(1_760_000_000, 0)
			script := []plane.Event{{Kind: plane.KindExec, PID: 1400, PPID: 1300, Name: "claude", Exe: "/home/dev/.local/bin/claude",
				ExecID: "root", UID: uidp(1001), At: base.Add(-time.Hour)}}
			script = append(script, hookLaunch(1401, base.Add(-250*time.Millisecond))...) // PreToolUse
			script = append(script,
				plane.Event{Kind: plane.KindExec, PID: 1410, PPID: 1400, Name: "bash", Exe: "/bin/bash", Cmdline: claudeEnvShell,
					ExecID: "env", ParentExecID: "root", UID: uidp(1001), At: base.Add(353 * time.Millisecond)},
				plane.Event{Kind: plane.KindExec, PID: 1411, PPID: 1400, Name: "bash", Exe: "/bin/bash", Cmdline: claudeSnapshotShell,
					ExecID: "snapshot", ParentExecID: "root", UID: uidp(1001), At: base.Add(371 * time.Millisecond)},
				plane.Event{Kind: plane.KindExec, PID: 1412, PPID: 1400, Name: "bash", Exe: "/bin/bash", Cmdline: claudeToolShell(command),
					ExecID: "tool", ParentExecID: "root", UID: uidp(1001), At: base.Add(475 * time.Millisecond)},
				plane.Event{Kind: plane.KindExec, PID: 1413, PPID: 1412, Name: "curl", Exe: "/usr/bin/curl", Cmdline: "/usr/bin/curl -s",
					ExecID: "child", ParentExecID: "tool", UID: uidp(1001), At: base.Add(480 * time.Millisecond)},
				plane.Event{Kind: plane.KindPolicyEvent, PolicyOwner: plane.PolicyOwnerCustomer, Policy: "dc-tg2-net-connect",
					PID: 1413, ExecID: "child", Name: "curl", UID: uidp(1001), At: base.Add(490 * time.Millisecond)},
			)
			host := newHost(newFake(fullCoverage(), script...))
			host.hooks = newHookRing(hookRingSize, hookRingWindow)
			host.hooks.record(HookDecision{
				Connector: "claudecode", SessionID: "sess-1", ToolInvocationID: "first-call",
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
			if join == nil || !join.Seen || join.ToolInvocationID != "first-call" || join.Confidence != want {
				t.Fatalf("first call join = %+v, want %s first-call", join, want)
			}
		})
	}
}

// A shell of the agent's that is no setup shell (a status line command) can
// take a command decision by time, but the tool's shell, whose command hashes
// match, still takes it exactly; no third shell takes it by time.
func TestHookRingExactMatchClaimsADecisionTakenByTime(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	ring := newHookRing(8, hookRingWindow)
	command := "cat /home/dev/tg2work/dccert-block-marker"
	ring.record(HookDecision{Connector: "claudecode", ToolInvocationID: "tool-1", CommandHash: HookCommandHash(command),
		PeerPID: 1401, PeerUID: 1001, At: base})
	rootOf := func(int) (int, bool) { return 1400, true }
	shell := func(cmdline string, after time.Duration) hookExec {
		return hookExec{RootPID: 1400, Connector: "claudecode", UID: uidp(1001), At: base.Add(after),
			Hashes: shellCommandHashes(cmdline), Shell: true}
	}
	if join := ring.join(shell(`/bin/bash -c "git branch --show-current"`, 100*time.Millisecond), rootOf); join.Confidence != HookJoinTemporal {
		t.Fatalf("status line shell join = %+v, want temporal", join)
	}
	if join := ring.join(shell(claudeToolShell(command), 200*time.Millisecond), rootOf); join.Confidence != HookJoinExact || join.ToolInvocationID != "tool-1" {
		t.Fatalf("tool shell join = %+v, want exact tool-1", join)
	}
	if join := ring.join(shell(`/bin/bash -c "date"`, 300*time.Millisecond), rootOf); join.Seen {
		t.Fatalf("a third shell took a decision joined twice: %+v", join)
	}
}

func TestIsAgentShellSetup(t *testing.T) {
	t.Parallel()
	for _, cmdline := range []string{claudeEnvShell, claudeSnapshotShell, `/usr/bin/bash -c -l SNAPSHOT_FILE=/tmp/s.sh`} {
		if !isAgentShellSetup("claudecode", cmdline) {
			t.Errorf("%q is Claude Code's setup shell", cmdline)
		}
		if isAgentShellSetup("codex", cmdline) {
			t.Errorf("%q is not a setup shell of codex", cmdline)
		}
	}
	for _, cmdline := range []string{
		claudeToolShell("env"), claudeToolShell("SNAPSHOT_FILE=x cat notes.txt"), `/bin/bash -c "env | grep PATH"`,
		"/usr/bin/env", "/bin/bash", "/bin/bash notes.sh",
	} {
		if isAgentShellSetup("claudecode", cmdline) {
			t.Errorf("%q is not a setup shell", cmdline)
		}
	}
}
