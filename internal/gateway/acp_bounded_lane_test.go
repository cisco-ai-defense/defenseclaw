// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// The ACP guard's caps in the cross-lane property test of the bound rule
// (bounded_lanes_test.go), each through the ACP frame judge with the guard's
// own tracker where the cap is the guard's:
//
//   - locations: a permission that names more than acpMaxFrameToolCalls
//     locations has the first ones judged and is then raised to the unknown
//     tier (rel-1-0-10:GAP-0296, GAP-0331);
//   - calls: the guard keeps the state of acp.MaxTrackedToolCalls tool calls;
//     a permission that names only the id of a call it dropped is judged at
//     the unknown tier (GAP-0374);
//   - bytes: the guard keeps at most acp.MaxToolCallStateBytes of a call; a
//     command that was cut keeps its prefix, which is still judged, and the
//     call is raised to the unknown tier (GAP-0374).
//
// The directory of a command that names none is the fourth bound of the ACP
// judge (the Paths cap): it is not a count, so it is not a row here; the
// property tests of acp_action_guard_test.go cover it in every pack.
func init() {
	registerBoundedLane(
		boundedLaneCap{
			lane: "s7/acp permission locations", cap: bounded.Locations, limit: acpMaxFrameToolCalls,
			gen: func(size int, shape boundedShape) (boundedLaneCall, bool) {
				if shape.nested || shape.multi {
					return boundedLaneCall{}, false // a permission has one list of locations
				}
				return acpBoundedCall("locations", size, shape.seen, shape.seenAfter), true
			},
			seen:      func() boundedLaneCall { return acpBoundedCall("locations", 1, true, false) },
			connector: "claudecode", // the connector the lane judges as (the ACP agent's)
			decide:    boundedDecideACP, judge: boundedDecideACP,
		},
		boundedLaneCap{
			// size is the number of other tool calls reported after the one the
			// permission names: at 255 it is still held, at 256 it is dropped.
			lane: "s7/acp kept tool calls", cap: bounded.Items, limit: acp.MaxTrackedToolCalls - 1,
			gen: func(size int, shape boundedShape) (boundedLaneCall, bool) {
				if shape.nested || shape.multi || shape.seenAfter {
					return boundedLaneCall{}, false
				}
				return acpBoundedCall("calls", size, shape.seen, false), true
			},
			seen:      func() boundedLaneCall { return acpBoundedCall("calls", 0, true, false) },
			connector: "claudecode", // the connector the lane judges as (the ACP agent's)
			decide:    boundedDecideACP, judge: boundedDecideACP,
		},
		boundedLaneCap{
			// size is the length of the command, which the guard keeps up to its
			// state bound (less the room of the other fields).
			lane: "s7/acp kept tool call bytes", cap: bounded.Bytes, limit: acp.MaxToolCallStateBytes - acpBoundedStateOverhead(),
			gen: func(size int, shape boundedShape) (boundedLaneCall, bool) {
				if shape.nested || shape.multi || shape.seenAfter {
					return boundedLaneCall{}, false // what follows the kept prefix is not judged
				}
				return acpBoundedCall("bytes", size, shape.seen, false), true
			},
			seen:      func() boundedLaneCall { return acpBoundedCall("bytes", 0, true, false) },
			connector: "claudecode", // the connector the lane judges as (the ACP agent's)
			decide:    boundedDecideACP, judge: boundedDecideACP,
		},
	)
}

// acpBoundedStateOverhead is the size of the kept state of the lane's call
// besides its command: the command is padded with a line break (two bytes of
// the state), so a command of size bytes makes a state of size+overhead.
func acpBoundedStateOverhead() int {
	var tracker acp.ToolCallTracker
	report := []byte(`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"tool_call","toolCallId":"t","kind":"execute","title":"Run","rawInput":{"command":""}}}}`)
	permission := []byte(`{"jsonrpc":"2.0","id":1,"method":"session/request_permission","params":{"sessionId":"s","toolCall":{"toolCallId":"t"},"options":[]}}`)
	first, _ := acp.ParseMessageAllowingNullIDErrors(report)
	second, _ := acp.ParseMessageAllowingNullIDErrors(permission)
	tracker.Commit(first, false)
	return len(tracker.Peek(second)) + 1 // the line break is escaped
}

func acpBoundedCall(lane string, size int, seen, seenAfter bool) boundedLaneCall {
	return boundedLaneCall{tool: "session/request_permission", input: map[string]any{
		"lane": lane, "size": size, "seen": seen, "seenAfter": seenAfter}}
}

// boundedDecideACP judges one generated permission through the ACP frame judge
// with the connector, profile and tier of api, as the gateway does for a frame
// of a guard whose session directory is env.cwd.
func boundedDecideACP(t *testing.T, api *APIServer, env boundedEnv, call boundedLaneCall) (string, []string) {
	t.Helper()
	lane, _ := call.input["lane"].(string)
	size, _ := call.input["size"].(int)
	seen, after := call.input["seen"] == true, call.input["seenAfter"] == true
	// The seen element: a write into the DefenseClaw state folder, which blocks
	// in every tier, as a location or as a command.
	state := filepath.Join(env.home, ".defenseclaw", "config.yaml")
	var toolCall map[string]any
	var guard json.RawMessage
	switch lane {
	case "locations":
		var locations []any
		count := size
		if seen {
			locations = append(locations, map[string]any{"path": state})
			count--
		}
		if after {
			count--
		}
		for i := 0; i < count; i++ {
			locations = append(locations, map[string]any{"path": filepath.Join(env.cwd, fmt.Sprintf("f%d.txt", i))})
		}
		if after {
			locations = append(locations, map[string]any{"path": state})
		}
		toolCall = map[string]any{"toolCallId": "t", "kind": "edit", "title": "Edit", "locations": locations}
	case "calls":
		var tracker acp.ToolCallTracker
		target := map[string]any{"sessionUpdate": "tool_call", "toolCallId": "t", "kind": "edit", "title": "Edit",
			"locations": []any{map[string]any{"path": filepath.Join(env.cwd, "target.txt")}}}
		tracker.Commit(acpParsedFrame(t, acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s", "update": target})), false)
		for i := 0; i < size; i++ {
			other := map[string]any{"sessionUpdate": "tool_call", "toolCallId": fmt.Sprintf("o%d", i), "kind": "read"}
			tracker.Commit(acpParsedFrame(t, acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s", "update": other})), false)
		}
		toolCall = map[string]any{"toolCallId": "t", "title": "Edit"}
		if seen {
			// The permission carries the seen element itself; the dropped state
			// of its call cannot hide it.
			toolCall["kind"] = "edit"
			toolCall["locations"] = []any{map[string]any{"path": state}}
		}
		guard = tracker.Peek(acpParsedFrame(t, acpFrameJSON(t, 1, "session/request_permission",
			map[string]any{"sessionId": "s", "options": []any{}, "toolCall": toolCall})))
	case "bytes":
		command := "ls"
		if seen {
			command = "printf changed >> " + state
		}
		if pad := size - len(command) - len("\n# "); pad > 0 {
			command += "\n# " + strings.Repeat("x", pad)
		}
		var tracker acp.ToolCallTracker
		report := map[string]any{"sessionUpdate": "tool_call", "toolCallId": "t", "kind": "execute", "title": "Run", "rawInput": map[string]any{"command": command}}
		tracker.Commit(acpParsedFrame(t, acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s", "update": report})), false)
		toolCall = map[string]any{"toolCallId": "t", "title": "Run"}
		guard = tracker.Peek(acpParsedFrame(t, acpFrameJSON(t, 1, "session/request_permission",
			map[string]any{"sessionId": "s", "options": []any{}, "toolCall": toolCall})))
	default:
		t.Fatalf("unknown ACP bound lane %q", lane)
	}
	frame := acpFrameJSON(t, 1, "session/request_permission", map[string]any{"sessionId": "s", "options": []any{}, "toolCall": toolCall})
	req := acp.Evaluation{Direction: acp.AgentToClient, Method: "session/request_permission", Payload: frame, SessionCWD: env.cwd, ToolCallState: guard}
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
