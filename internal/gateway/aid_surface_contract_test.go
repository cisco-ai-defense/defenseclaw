// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The registry's AID surface declaration has to describe what the hook lane
// actually does with each event, or it documents rather than governs. For every
// contract event, the runtime classification and the declaration must agree.
func TestAIDSurfaceEventsMatchRuntimeClassification(t *testing.T) {
	registry := connector.NewDefaultRegistry()
	for _, name := range registry.Names() {
		for _, contract := range connector.KnownHookContracts(name) {
			declared := func(surface string, event string) bool {
				for _, candidate := range contract.AIDSurfaceEvents[surface] {
					if candidate == event {
						return true
					}
				}
				return false
			}
			carries := func(surface string) bool {
				for _, candidate := range contract.AIDSurfaces {
					if candidate == surface {
						return true
					}
				}
				return false
			}
			for _, event := range contract.Events {
				t.Run(contract.ContractID+"/"+event, func(t *testing.T) {
					if carries(connector.AIDSurfacePrompt) {
						if got, want := declared(connector.AIDSurfacePrompt, event), isPromptLikeEvent(event); got != want {
							t.Errorf("prompt surface declared=%v, runtime=%v", got, want)
						}
					}
					if carries(connector.AIDSurfaceToolResult) {
						if got, want := declared(connector.AIDSurfaceToolResult, event), isResultLikeEvent(event); got != want {
							t.Errorf("tool_result surface declared=%v, runtime=%v", got, want)
						}
					}
					if carries(connector.AIDSurfaceToolCall) {
						routed := contract.ToolCallLifecycle.RouteForEvent(event) == connector.ToolEventRouteStructuredAction
						if got := declared(connector.AIDSurfaceToolCall, event); got != routed {
							t.Errorf("tool_call surface declared=%v, routed=%v", got, routed)
						}
					}
				})
			}
		}
	}
}

// Every contract that sends anything to AID names the encoding it sends.
func TestAIDWireVersionDeclaredForEveryAIDSurface(t *testing.T) {
	registry := connector.NewDefaultRegistry()
	for _, name := range registry.Names() {
		for _, contract := range connector.KnownHookContracts(name) {
			if len(contract.AIDSurfaces) == 0 {
				continue
			}
			if contract.AIDWireVersion != connector.AIDWireVersionChatToolCalls {
				t.Errorf("%s aid_wire_version=%q want %q",
					contract.ContractID, contract.AIDWireVersion, connector.AIDWireVersionChatToolCalls)
			}
		}
	}
}
