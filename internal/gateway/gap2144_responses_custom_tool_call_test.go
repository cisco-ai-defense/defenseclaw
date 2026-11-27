// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"
)

// TestGAP2144ResponsesCustomToolCallCommandIsJudgedAsTheToolCall
// (rel-1-0-10:GAP-2144): an OpenAI Responses reply whose custom_tool_call
// (free-form tool) input is a shell command was forwarded, in every tier,
// where the same command as a function_call item was blocked: the body
// extractor read only function_call items, and a free-form input reached the
// tool-call rules as text that is no argument object. Now the custom tool's
// input is the tool's call (a shell tool's command), on the body route and
// for a free-form input on the shared tool-call inspection, so the
// custom_tool_call is never weaker than its function_call twin; the benign
// twin stays forwarded.
func TestGAP2144ResponsesCustomToolCallCommandIsJudgedAsTheToolCall(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	attack := "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	benign := "ls -la"
	reply := func(kind, command string) []byte {
		item := map[string]any{"type": kind, "id": "it", "name": "Bash", "call_id": "c"}
		if kind == "custom_tool_call" {
			item["input"] = command
		} else {
			args, _ := json.Marshal(map[string]string{"command": command})
			item["arguments"] = string(args)
		}
		body, _ := json.Marshal(map[string]any{"id": "r", "object": "response", "output": []any{item}})
		return body
	}
	for _, p := range gap0437Packs {
		proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
		proxy.cfg.RulePack = p.pack
		installToolCallCorpusProfileConnector(t, proxy.connectorName(), p.pack)
		judge := func(body []byte) string {
			calls := extractPassthroughToolCalls(body, "openai")
			if calls == nil {
				return "uninspected"
			}
			if v := proxy.inspectToolCalls(context.Background(), calls); v != nil {
				return v.Action
			}
			return "allow"
		}
		control := judge(reply("function_call", attack))
		if control == "allow" || control == "uninspected" {
			t.Fatalf("%s: the function_call control is %q; the fixture no longer proves anything", p.name, control)
		}
		if got := judge(reply("custom_tool_call", attack)); shapeParityRank[got] < shapeParityRank[control] {
			t.Errorf("%s: custom_tool_call command %q, function_call twin %q", p.name, got, control)
		}
		if got := judge(reply("custom_tool_call", benign)); got == "block" {
			t.Errorf("%s: benign custom_tool_call blocked", p.name)
		}
		// The shared inspection of a free-form input (the stream route
		// passes custom_tool_call_input text as the call's arguments).
		raw, _ := json.Marshal([]map[string]any{{"type": "function", "function": map[string]string{"name": "Bash", "arguments": attack}}})
		got := "allow"
		if v := proxy.inspectToolCalls(context.Background(), raw); v != nil {
			got = v.Action
		}
		if shapeParityRank[got] < shapeParityRank[control] {
			t.Errorf("%s: free-form Bash input %q, function_call twin %q", p.name, got, control)
		}
	}
}
