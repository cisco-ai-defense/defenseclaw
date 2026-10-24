// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

func TestPerUserHookRenderCannotOpenOnGatewayFailure(t *testing.T) {
	for _, conn := range []Connector{
		NewCodexConnector(), NewClaudeCodeConnector(), NewCursorConnector(),
		NewOpenCodeConnector(), NewAMPConnector(),
	} {
		for _, mode := range []string{"observe", "action"} {
			opts := SetupOpts{GuardrailMode: mode, HookFailMode: "open", ConfiguredHookFailMode: "open"}
			if got := resolveHookFailMode(opts, conn); got != "closed" {
				t.Errorf("%s/%s: rendered fail mode = %q, want closed", conn.Name(), mode, got)
			}
			if got := OutageHookFailMode(opts, conn); got != "closed" {
				t.Errorf("%s/%s: outage fail mode = %q, want closed", conn.Name(), mode, got)
			}
			if got := renderedHookFailMode(opts, conn); got != "closed" {
				t.Errorf("%s/%s: installed hook fail mode = %q, want closed", conn.Name(), mode, got)
			}
		}
	}
}
