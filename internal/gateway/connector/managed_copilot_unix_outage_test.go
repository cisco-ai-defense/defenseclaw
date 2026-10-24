// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"strings"
	"testing"
)

// The managed per-user-route Copilot hook on Linux and macOS: copilot-hook.sh
// on the hook socket, the route a standalone install uses when Copilot's
// machine policy is off (the machine-policy hook is defenseclaw-hook
// --enterprise-managed, which follows the administrator's mode; hookexec
// TestManagedCopilotOutageFollowsTheFailMode). It renders FAIL_MODE closed
// and answers every failure with Copilot's native deny
// (copilot_managed_failure), whatever the administrator chose, which is what
// HookOutage.ManagedOpenUnixPerUserRoute says and the gateway outage table
// shows. This runs the real render with the gateway service up (the call is
// answered, no deny) and stopped (hook socket gone) in both installed modes
// and for both blockable events.
func TestManagedUnixPerUserRouteCopilotOutageFollowsHookOutage(t *testing.T) {
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		if _, err := os.Stat("/usr/local/bin/jq"); err != nil {
			t.Skip("jq is required to run the Copilot shell hook")
		}
	}
	outage := ConnectorHookOutage(NewCopilotConnector())
	denies := map[string]string{
		"preToolUse":        `"permissionDecision":"deny"`,
		"permissionRequest": `"behavior":"deny"`,
	}
	payload := `{"cwd":"/tmp","toolName":"bash","toolArgs":"{\"command\":\"echo marker\"}"}`
	for _, mode := range []string{"open", "closed"} {
		wantDeny := mode == "closed" || outage.ManagedOpenUnixPerUserRoute == OutageBlocks
		for event, deny := range denies {
			t.Run(mode+"/"+event, func(t *testing.T) {
				f := newHookSocketFixture(t, "dcuc", map[string]interface{}{"action": "allow", "hook_output": map[string]string{}})
				args := []string{"--event", event}
				code, stdout, stderr := runStandaloneShellHookInMode(t, f, NewCopilotConnector(), "copilot-hook.sh", args, payload, mode)
				if code != 0 || strings.Contains(stdout, "deny") {
					t.Fatalf("running gateway answered allow: exit %d stdout=%q stderr=%q, want no deny", code, stdout, stderr)
				}
				if err := os.Remove(f.socket); err != nil {
					t.Fatal(err)
				}
				code, stdout, stderr = runStandaloneShellHookInMode(t, f, NewCopilotConnector(), "copilot-hook.sh", args, payload, mode)
				if denied := strings.Contains(stdout, deny); code != 0 || denied != wantDeny {
					t.Fatalf("installed mode %q, gateway stopped: exit %d stdout=%q stderr=%q, want Copilot's native deny %s = %v (HookOutage %q)",
						mode, code, stdout, stderr, deny, wantDeny, outage.ManagedOpenUnixPerUserRoute)
				}
			})
		}
	}
}
