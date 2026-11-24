// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestGAP1654KiroPostDedupeKeysOnTheOutput: kiro-cli 3.x delivers one tool
// call's post on two surfaces. When the second surface's delivery of call A
// goes missing, a later call B with the same arguments but another output
// must be judged on its own output, not take A's post verdict. The two
// deliveries of one call (same output) still pair.
func TestGAP1654KiroPostDedupeKeysOnTheOutput(t *testing.T) {
	ctx := context.Background()
	post := func(surface, output string) agentHookRequest {
		req := kiroDedupeRequest(surface, "execute_bash", "cat notes.txt")
		req.HookEventName = "postToolUse"
		req.Payload["tool_response"] = map[string]interface{}{"success": true, "result": []interface{}{output}}
		return req
	}
	alert := agentHookResponse{Action: "alert", Severity: "HIGH", EvaluationID: "post-a"}

	var d copilotHookDedupe
	_, hit, first := d.begin(ctx, "kiro", post("", "first output"), "")
	if hit {
		t.Fatal("first post delivery hit")
	}
	first.complete(alert)
	// The v3 delivery of call A never came. Call B, same arguments, other output:
	if got, hit, _ := d.begin(ctx, "kiro", post(connector.KiroHookSurfaceV3, "another output"), ""); hit {
		t.Fatalf("a post with another output took the earlier post verdict: %+v", got)
	}

	var pair copilotHookDedupe
	_, _, a := pair.begin(ctx, "kiro", post("", "same output"), "")
	a.complete(alert)
	if got, hit, _ := pair.begin(ctx, "kiro", post(connector.KiroHookSurfaceV3, "same output"), ""); !hit || got.EvaluationID != "post-a" {
		t.Fatalf("the second surface's post of the same call did not pair: hit=%v got=%+v", hit, got)
	}
}

// Copilot's two CLI dialects pair one call's post: camelCase toolResult
// (textResultForLlm) and the snake_case tool_response string of the same
// output. Another output with the same arguments does not pair.
func TestGAP1654CopilotPostDedupeKeysOnTheOutput(t *testing.T) {
	ctx := context.Background()
	camel := func(output string) agentHookRequest {
		args := json.RawMessage(`"{\"command\":\"cat notes.txt\"}"`)
		return agentHookRequest{HookEventName: "postToolUse", SessionID: "cp-s1", CWD: "/project", ToolName: "bash", ToolArgs: args,
			Payload: map[string]interface{}{"toolName": "bash", "toolArgs": string(args),
				"toolResult": map[string]interface{}{"resultType": "success", "textResultForLlm": output}}}
	}
	snake := func(output string) agentHookRequest {
		args := json.RawMessage(`{"command":"cat notes.txt"}`)
		return agentHookRequest{HookEventName: "PostToolUse", SessionID: "cp-s1", CWD: "/project", ToolName: "bash", ToolArgs: args,
			Payload: map[string]interface{}{"tool_name": "bash", "tool_input": map[string]interface{}{"command": "cat notes.txt"},
				"tool_response": output}}
	}
	alert := agentHookResponse{Action: "alert", Severity: "HIGH", EvaluationID: "cp-a"}

	var pair copilotHookDedupe
	_, _, a := pair.begin(ctx, "copilot", camel("same output"), "")
	a.complete(alert)
	if got, hit, _ := pair.begin(ctx, "copilot", snake("same output"), ""); !hit || got.EvaluationID != "cp-a" {
		t.Fatalf("the other dialect's post of the same call did not pair: hit=%v got=%+v", hit, got)
	}

	var d copilotHookDedupe
	_, _, first := d.begin(ctx, "copilot", camel("first output"), "")
	first.complete(alert)
	if got, hit, _ := d.begin(ctx, "copilot", snake("another output"), ""); hit {
		t.Fatalf("a post with another output took the earlier post verdict: %+v", got)
	}
}
