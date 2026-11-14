// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// overLimitWindowsRedirect is a PowerShell append to the Windows
// authorized_keys file, the call GAP-0611 let through when padded.
const overLimitWindowsRedirect = `echo ssh-ed25519 AAAAdccertmarker3 dccert-c >> C:\Users\alice\.ssh\authorized_keys`

// overLimitWindowsPaddings are the comment paddings that take the command
// past maxCommandBytes: after the command, before it, and both (the padded
// forms of TestACPPermissionAfterABlockedReportIsNeverBelowTheBlock).
func overLimitWindowsPaddings(command string) map[string]string {
	return map[string]string{
		"trailing": command + "\n# " + strings.Repeat("y", acp.MaxToolCallStateBytes),
		"leading":  "# " + strings.Repeat("x", 70<<10) + "\n" + command,
		"both":     "# " + strings.Repeat("x", 9<<10) + "\n" + command + "\n# " + strings.Repeat("y", acp.MaxToolCallStateBytes),
	}
}

// TestOverLimitWindowsCommandTwinKeepsTheHooksDialect: a Windows hook cannot
// choose a shell dialect for a command past the string limit, so the bounded
// twin is placed in the dialect the unpadded call gets. A call the hook did not
// place, and a host that places none, keep their hint (rel-1-0-10:GAP-0611).
func TestOverLimitWindowsCommandTwinKeepsTheHooksDialect(t *testing.T) {
	for name, padded := range overLimitWindowsPaddings(overLimitWindowsRedirect) {
		args, err := json.Marshal(map[string]string{"command": padded})
		if err != nil {
			t.Fatal(err)
		}
		input := actionfacts.Input{Tool: "shell", Args: args, CWD: `C:\Users\alice`}
		facts := actionfacts.Analyze(input)
		if facts.Parse.Status != actionfacts.StatusLimitExceeded {
			t.Fatalf("%s: the padded command is not past the limit: %s", name, facts.Parse.Status)
		}
		for connector, want := range map[string]actionfacts.Dialect{
			"kiro": actionfacts.DialectPowerShell, "codex": actionfacts.DialectPowerShell,
			// Claude Code places a Bash call only when Git Bash reads it alone.
			"claudecode": "",
		} {
			request := trustedActionRequest{Input: input, Connector: connector, windowsDialectReadings: true}
			twin, ok := overLimitCommandBoundedTwinRequest(request, facts)
			if !ok {
				t.Fatalf("%s/%s: no bounded twin", name, connector)
			}
			if got := twin.Input.DialectHint; got != want {
				t.Errorf("%s/%s: the twin is read as %q, want %q", name, connector, got, want)
			}
		}
		// Not a Windows hook, or a hook that placed the call: unchanged.
		twin, ok := overLimitCommandBoundedTwinRequest(trustedActionRequest{Input: input, Connector: "kiro"}, facts)
		if !ok || twin.Input.DialectHint != "" {
			t.Errorf("%s: a call no Windows hook placed got the hint %q", name, twin.Input.DialectHint)
		}
		placed := input
		placed.DialectHint = actionfacts.DialectCMD
		twin, ok = overLimitCommandBoundedTwinRequest(trustedActionRequest{Input: placed, Connector: "kiro", windowsDialectReadings: true}, actionfacts.Analyze(placed))
		if !ok || twin.Input.DialectHint != actionfacts.DialectCMD {
			t.Errorf("%s: a call the hook placed in CMD got the hint %q", name, twin.Input.DialectHint)
		}
	}
}

// TestOverLimitWindowsCommandKeepsItsBlockOnTheKiroHook: on a Windows hook a
// protected redirect keeps its block however the command is padded past the
// string limit, in every pack, as the unpadded call, and an ordinary padded
// command stays allowed (rel-1-0-10:GAP-0611).
func TestOverLimitWindowsCommandKeepsItsBlockOnTheKiroHook(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	const ordinary = `Get-ChildItem C:\Users\alice\project`
	for _, pack := range []string{"default", "permissive", "strict"} {
		env := newACPActionEnv(t, pack)
		for _, tool := range []string{"execute_pwsh", "execute_bash"} {
			unpadded, rules := env.kiroHook(t, tool, map[string]any{"command": overLimitWindowsRedirect}, true)
			if !acpBlocked(unpadded) {
				t.Fatalf("%s/%s: the unpadded redirect is %s %v, not a block", pack, tool, unpadded, rules)
			}
			for name, padded := range overLimitWindowsPaddings(overLimitWindowsRedirect) {
				if got, rules := env.kiroHook(t, tool, map[string]any{"command": padded}, true); !acpBlocked(got) {
					t.Errorf("%s/%s/%s: the padded redirect is %s %v, want the block of the unpadded call", pack, tool, name, got, rules)
				}
			}
			for name, padded := range overLimitWindowsPaddings(ordinary) {
				if got, rules := env.kiroHook(t, tool, map[string]any{"command": padded}, true); acpBlocked(got) {
					t.Errorf("%s/%s/%s: an ordinary padded command is %s %v", pack, tool, name, got, rules)
				}
			}
		}
	}
}
