// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

// oss-outage-open: a per-user render bakes closed for every failure
// (resolveHookFailMode) and records the outage mode its caller resolved from
// the policy tier (config.HookOutageFailMode) in its runtime records: open in
// the default and permissive tiers, closed in strict and for an empty or
// unknown value. The guardrail mode does not change either.
func TestPerUserHookRenderBakesClosedAndRecordsTheOutageMode(t *testing.T) {
	for _, conn := range []Connector{
		NewCodexConnector(), NewClaudeCodeConnector(), NewCursorConnector(), NewCopilotConnector(),
		NewHermesConnector(), NewAntigravityConnector(), NewOpenCodeConnector(), NewAMPConnector(),
	} {
		for _, mode := range []string{"observe", "action"} {
			for outage, want := range map[string]string{"open": "open", "closed": "closed", "": "closed", "Open ": "open", "bogus": "closed"} {
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
