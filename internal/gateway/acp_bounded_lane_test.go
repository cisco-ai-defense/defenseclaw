// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// The ACP guard's cap in the cross-lane property test of the bound rule
// (bounded_lanes_test.go): a session/request_permission that names more
// locations than acpMaxFrameToolCalls has the first ones judged and is then
// raised to the unknown tier of the pack in every tier, and a block among the
// judged ones (the seen element, a write into the DefenseClaw state folder)
// still decides past the cap (rel-1-0-10:GAP-0296, GAP-0331).
func init() {
	registerBoundedLane(boundedLaneCap{
		lane: "s7/acp permission locations", cap: bounded.Locations, limit: acpMaxFrameToolCalls, adopted: true,
		gen: func(size int, shape boundedShape) boundedLaneCall {
			return boundedLaneCall{tool: "session/request_permission", input: map[string]any{"locations": size, "seen": shape.seen}}
		},
		decide: boundedDecideACPPermission,
	})
}

// boundedDecideACPPermission judges one generated permission through the ACP
// frame judge with the connector, profile and tier of api, as the gateway does
// for a frame of a guard whose session directory is env.cwd.
func boundedDecideACPPermission(t *testing.T, api *APIServer, env boundedEnv, call boundedLaneCall) (string, []string) {
	t.Helper()
	count, _ := call.input["locations"].(int)
	var locations []any
	if call.input["seen"] == true {
		locations = append(locations, map[string]any{"path": filepath.Join(env.home, ".defenseclaw", "config.yaml")})
		count--
	}
	for i := 0; i < count; i++ {
		locations = append(locations, map[string]any{"path": filepath.Join(env.cwd, fmt.Sprintf("f%d.txt", i))})
	}
	frame := acpFrameJSON(t, 1, "session/request_permission", map[string]any{"sessionId": "s", "options": []any{},
		"toolCall": map[string]any{"toolCallId": "t", "kind": "edit", "title": "Edit", "locations": locations}})
	req := acp.Evaluation{Direction: acp.AgentToClient, Method: "session/request_permission", Payload: frame, SessionCWD: env.cwd}
	action, isAction := acpFrameToolCalls(req, runtime.GOOS)
	if !isAction {
		t.Fatal("a permission is not an action frame")
	}
	ctx := withProfilePath(acpEvaluationContext(context.Background(), req, "claudecode", false), profilePathHook)
	ctx = api.withGuardrailProfileDecision(ctx, "claudecode")
	verdict, _ := api.inspectACPFrameAction(ctx, req, "claudecode", action, nil)
	if verdict == nil {
		t.Fatal("no verdict")
	}
	return verdict.Action, verdict.Findings
}
