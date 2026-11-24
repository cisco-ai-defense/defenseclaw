// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
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

// Copilot's two CLI dialects carry the output as a toolResult object
// (camelCase) or a plain string; both reduce to the same text.
func TestGAP1654CopilotToolResultDigestOneForm(t *testing.T) {
	camel := copilotToolResultDigest(map[string]interface{}{"toolResult": map[string]interface{}{"resultType": "success", "textResultForLlm": "out"}})
	snake := copilotToolResultDigest(map[string]interface{}{"tool_response": "out"})
	if camel != snake {
		t.Fatalf("camel %s != snake %s", camel, snake)
	}
	if copilotToolResultDigest(map[string]interface{}{"tool_response": "other"}) == snake {
		t.Fatal("another output hashed the same")
	}
	if copilotToolResultDigest(nil) != copilotToolResultDigest(map[string]interface{}{}) {
		t.Fatal("two deliveries without output do not pair")
	}
}
