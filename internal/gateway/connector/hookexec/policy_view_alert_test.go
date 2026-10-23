// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"testing"
)

// Review loop round 2 (P1): the policy-view alert of a standalone managed
// hook rides on the inspected call. The hook sends exactly one request,
// carries ClientAlertHeader with the fixed reason only when it could not
// prove the view, and still gets the gateway's verdict for the call. No
// other hook profile sends the header.
func TestManagedPolicyViewAlertRidesOnTheInspectedCall(t *testing.T) {
	for _, tc := range []struct {
		name       string
		managed    bool
		standalone bool
		alert      bool
		want       string
	}{
		{name: "standalone with an unproven view", managed: true, standalone: true, alert: true, want: ManagedPolicyViewReason},
		{name: "standalone with a proven view", managed: true, standalone: true},
		{name: "managed without the standalone transport", managed: true, alert: true},
		{name: "per-user hook", alert: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := ok(`{"action":"block","reason":"policy"}`)
			result := run(t, "claudecode", rt, func(o *Options) {
				o.FailMode = "closed"
				o.ManagedEnterprise = tc.managed
				if tc.managed {
					token := "authenticated-generation-token"
					o.AuthenticatedManagedToken = &token
				}
				o.ManagedStandalone = tc.standalone
				if tc.standalone {
					o.ManagedUnixSocket = "/not-used-by-the-test-client/hook.sock"
				}
				o.ManagedPolicyViewAlert = tc.alert
				o.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`)
			})
			if rt.requests != 1 {
				t.Fatalf("requests = %d, want the call alone", rt.requests)
			}
			if got := rt.gotReq.Header.Get(ClientAlertHeader); got != tc.want {
				t.Fatalf("%s = %q, want %q", ClientAlertHeader, got, tc.want)
			}
			if !claudeBlocked(result) {
				t.Fatalf("the gateway's block was not applied: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
			}
		})
	}
}
