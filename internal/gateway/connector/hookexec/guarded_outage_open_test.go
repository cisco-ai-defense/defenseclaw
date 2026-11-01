// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// GAP-0352: once the foreign-hook guard leaves an outage call of a guarded
// connector to the hook (the gateway's clean-session entry vouched for the
// agent process), the hook's own request meets the stopped gateway and the
// managed outage rule decides: the administrator's open runs it, closed and
// strict availability block it, and a gateway that is not proven stopped
// blocks it in every mode.
func TestGuardedConnectorsFollowTheManagedOutageFailMode(t *testing.T) {
	notRunning := fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
	calls := map[string]struct{ event, stdin string }{
		"copilot":  {"preToolUse", `{"toolName":"bash","toolArgs":"{\"command\":\"ls\"}","sessionId":"s-1"}`},
		"cursor":   {"beforeShellExecution", `{"hook_event_name":"beforeShellExecution","command":"ls","conversation_id":"s-1"}`},
		"devin":    {"PreToolUse", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"session_id":"s-1"}`},
		"opencode": {"tool.execute.before", `{"hook_event_name":"tool.execute.before","tool":"bash","args":{"command":"ls"},"session_id":"s-1"}`},
	}
	for id, call := range calls {
		for _, tc := range []struct {
			name    string
			err     error
			mode    string
			strict  bool
			blocked bool
		}{
			{name: "open, stopped gateway", err: notRunning, mode: "open"},
			{name: "closed, stopped gateway", err: notRunning, mode: "closed", blocked: true},
			{name: "strict availability", err: notRunning, mode: "open", strict: true, blocked: true},
			{name: "open, gateway not proven stopped", err: errors.New("offline"), mode: "open", blocked: true},
		} {
			t.Run(id+"/"+tc.name, func(t *testing.T) {
				result := run(t, id, &stubRT{err: tc.err}, func(o *Options) {
					managedCodex(o)
					o.ExplainUnenrolledAccount = true
					o.FailMode = tc.mode
					o.StrictAvailability = tc.strict
					o.Event = call.event
					o.Stdin = strings.NewReader(call.stdin)
				})
				if blocked(result) != tc.blocked {
					t.Fatalf("blocked = %v, want %v: code=%d stdout=%q stderr=%q", blocked(result), tc.blocked, result.code, result.stdout, result.stderr)
				}
			})
		}
	}
}
