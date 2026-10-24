// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

// A per-user render bakes and records closed for every failure, including an
// outage, even when an older config or lock supplies open.
func TestPerUserHookRenderBakesClosedAndRecordsTheOutageMode(t *testing.T) {
	for _, conn := range []Connector{
		NewCodexConnector(), NewClaudeCodeConnector(), NewCursorConnector(), NewCopilotConnector(),
		NewHermesConnector(), NewAntigravityConnector(), NewOpenCodeConnector(), NewAMPConnector(),
	} {
		for _, mode := range []string{"observe", "action"} {
			for outage, want := range map[string]string{"open": "closed", "closed": "closed", "": "closed", "Open ": "closed", "bogus": "closed"} {
				opts := SetupOpts{GuardrailMode: mode, HookFailMode: outage}
				if got := resolveHookFailMode(opts, conn); got != "closed" {
					t.Errorf("%s/%s/%q: baked fail mode = %q, want closed", conn.Name(), mode, outage, got)
				}
				if got := OutageHookFailMode(opts, conn); got != want {
					t.Errorf("%s/%s/%q: outage fail mode = %q, want %q", conn.Name(), mode, outage, got, want)
				}
				if got := renderedHookFailMode(opts, conn); got != want {
					t.Errorf("%s/%s/%q: recorded hook fail mode = %q, want %q", conn.Name(), mode, outage, got, want)
				}
			}
		}
	}
}
