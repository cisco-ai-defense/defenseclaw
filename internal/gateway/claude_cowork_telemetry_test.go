// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// A Cowork hook decision record carries defenseclaw.agent.surface=cowork; a
// terminal call's record leaves it out.
func TestHookDecisionV8NamesTheCoworkSurface(t *testing.T) {
	for _, cowork := range []bool{true, false} {
		api, capture := bindHookModelV8Runtime(t, []string{"logs"})
		ctx := context.Background()
		if cowork {
			ctx = withCowork(ctx, coworkHeader(hookexec.CoworkContext{SessionID: "s-1"}), "claudecode")
		}
		req := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse", SessionID: "session-cowork-1", ToolName: "mcp__workspace__bash"}
		resp := agentHookResponse{Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action"}
		api.emitHookDecisionObservabilityV8(ctx, req, resp, HookAuditEnvelope{ElapsedMs: 1}, false)
		eventuallyTrue(t, func() bool { return len(hookModelV8CapturedLogs(capture.logSnapshot())) >= 1 })
		logs := hookModelV8CapturedLogs(capture.logSnapshot())
		var wire struct {
			Body map[string]interface{} `json:"body"`
		}
		if len(logs) != 1 || json.Unmarshal([]byte(logs[0].Body.GetStringValue()), &wire) != nil {
			t.Fatalf("cowork=%v: logs=%d, want one with a JSON body", cowork, len(logs))
		}
		got, present := wire.Body["defenseclaw.agent.surface"]
		if !present {
			for _, attribute := range logs[0].Attributes {
				if attribute.Key == "defenseclaw.agent.surface" {
					got, present = attribute.Value.GetStringValue(), true
				}
			}
		}
		if cowork && (!present || got != "cowork") {
			t.Errorf("Cowork decision surface = %v (present %v), want cowork; body %v", got, present, wire.Body)
		}
		if !cowork && present {
			t.Errorf("terminal decision carries surface %v", got)
		}
	}
}
