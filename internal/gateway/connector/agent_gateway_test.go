// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

var agentGatewayValidEvents = map[string]string{
	"session_start":  `{"event":"session_start","session_id":"s1"}`,
	"session_end":    `{"event":"session_end","session_id":"s1"}`,
	"user_prompt":    `{"event":"user_prompt","session_id":"s1","prompt":"tidy the repo"}`,
	"pre_tool shell": `{"event":"pre_tool","session_id":"s1","tool_use_id":"t1","cwd":"/work","tool":{"name":"bash","kind":"shell","input":"ls -la"}}`,
	"pre_tool obj":   `{"event":"pre_tool","session_id":"s1","tool_use_id":"t1","tool":{"name":"run","kind":"shell","input":{"command":"ls"}}}`,
	"pre_tool read":  `{"event":"pre_tool","session_id":"s1","tool_use_id":"t1","tool":{"name":"read","kind":"file_read","input":"/etc/hosts"}}`,
	"pre_tool write": `{"event":"pre_tool","session_id":"s1","tool_use_id":"t1","tool":{"name":"write","kind":"file_write","input":{"path":"/work/a.txt","content":"x"}}}`,
	"pre_tool fetch": `{"event":"pre_tool","session_id":"s1","tool_use_id":"t1","tool":{"name":"get","kind":"fetch","input":"https://example.com"}}`,
	"pre_tool mcp":   `{"event":"pre_tool","session_id":"s1","tool_use_id":"t1","tool":{"name":"github.create_issue","kind":"mcp","input":{"title":"x"}}}`,
	"post_tool":      `{"event":"post_tool","session_id":"s1","tool_use_id":"t1","tool":{"name":"bash","kind":"shell","input":"ls"},"tool_response":{"stdout":"a"},"status":"success"}`,
	"subagent_start": `{"event":"subagent_start","session_id":"s2","parent_session_id":"s1"}`,
	"subagent_stop":  `{"event":"subagent_stop","session_id":"s2","parent_session_id":"s1"}`,
	"identity":       `{"event":"session_start","session_id":"s1","acting_for":{"user":"eng1"},"root_session_id":"r1","traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}`,
}

var agentGatewayInvalidEvents = map[string]string{
	"empty":                 ``,
	"not json":              `{"event":`,
	"trailing":              `{"event":"session_start","session_id":"s1"} {}`,
	"unknown field":         `{"event":"session_start","session_id":"s1","hook_event_name":"PreToolUse"}`,
	"duplicate key":         `{"event":"session_start","event":"pre_tool","session_id":"s1"}`,
	"unknown event":         `{"event":"PreToolUse","session_id":"s1"}`,
	"no session":            `{"event":"session_start"}`,
	"tool on session":       `{"event":"session_start","session_id":"s1","tool":{"name":"x","kind":"other"}}`,
	"pre_tool no tool":      `{"event":"pre_tool","session_id":"s1","tool_use_id":"t1"}`,
	"pre_tool no use id":    `{"event":"pre_tool","session_id":"s1","tool":{"name":"x","kind":"shell","input":"ls"}}`,
	"bad kind":              `{"event":"pre_tool","session_id":"s1","tool_use_id":"t1","tool":{"name":"x","kind":"exec","input":"ls"}}`,
	"tool unknown field":    `{"event":"pre_tool","session_id":"s1","tool_use_id":"t1","tool":{"name":"x","kind":"shell","input":"ls","dialect":"bash"}}`,
	"post_tool no response": `{"event":"post_tool","session_id":"s1","tool_use_id":"t1","tool":{"name":"x","kind":"shell","input":"ls"}}`,
	"prompt on pre_tool":    `{"event":"pre_tool","session_id":"s1","tool_use_id":"t1","prompt":"x","tool":{"name":"x","kind":"shell","input":"ls"}}`,
	"user_prompt no prompt": `{"event":"user_prompt","session_id":"s1"}`,
	"subagent no parent":    `{"event":"subagent_start","session_id":"s2"}`,
	"parent on session":     `{"event":"session_start","session_id":"s2","parent_session_id":"s1"}`,
	"acting_for unknown":    `{"event":"session_start","session_id":"s1","acting_for":{"user":"eng1","groups":["admins"]}}`,
	"acting_for empty":      `{"event":"session_start","session_id":"s1","acting_for":{"user":""}}`,
	"bad traceparent":       `{"event":"session_start","session_id":"s1","traceparent":"00-xyz"}`,
	"padded session":        `{"event":"session_start","session_id":" s1"}`,
	"relative cwd":          `{"event":"pre_tool","session_id":"s1","tool_use_id":"t1","cwd":"work","tool":{"name":"x","kind":"shell","input":"ls"}}`,
	"tool name with space":  `{"event":"pre_tool","session_id":"s1","tool_use_id":"t1","tool":{"name":"run it","kind":"other"}}`,
	"duplicate nested key":  `{"event":"pre_tool","session_id":"s1","tool_use_id":"t1","tool":{"name":"x","kind":"shell","kind":"other","input":"ls"}}`,
	"status on pre_tool":    `{"event":"pre_tool","session_id":"s1","tool_use_id":"t1","status":"success","tool":{"name":"x","kind":"shell","input":"ls"}}`,
	"bad status":            `{"event":"post_tool","session_id":"s1","tool_use_id":"t1","status":"done","tool":{"name":"x","kind":"shell","input":"ls"},"tool_response":{}}`,
}

func TestDecodeAgentGatewayEvent(t *testing.T) {
	for name, body := range agentGatewayValidEvents {
		if _, err := DecodeAgentGatewayEvent([]byte(body)); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	for name, body := range agentGatewayInvalidEvents {
		_, err := DecodeAgentGatewayEvent([]byte(body))
		var contract *AgentGatewayContractError
		if err == nil || !errors.As(err, &contract) || contract.Reason == "" {
			t.Errorf("%s: err = %v, want a contract refusal", name, err)
		}
	}
}

// The published JSON schema and the decoder agree on every example.
func TestAgentGatewaySchemaMatchesDecoder(t *testing.T) {
	path := filepath.Join("..", "..", "..", "schemas", "connectors", "agent-gateway-hook.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	if err := compiler.AddResource("agent-gateway-hook.json", bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("agent-gateway-hook.json")
	if err != nil {
		t.Fatal(err)
	}
	check := func(name, body string, want bool) {
		var doc interface{}
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			if want {
				t.Errorf("%s: not JSON", name)
			}
			return
		}
		if got := schema.Validate(doc) == nil; got != want {
			t.Errorf("%s: schema valid=%v, decoder valid=%v", name, got, want)
		}
	}
	for name, body := range agentGatewayValidEvents {
		check(name, body, true)
	}
	for _, name := range []string{
		"unknown field", "unknown event", "no session", "tool on session", "pre_tool no tool", "pre_tool no use id",
		"bad kind", "tool unknown field", "post_tool no response", "prompt on pre_tool", "user_prompt no prompt",
		"subagent no parent", "parent on session", "acting_for unknown", "acting_for empty", "bad traceparent",
		"padded session", "tool name with space", "status on pre_tool", "bad status",
	} {
		check(name, agentGatewayInvalidEvents[name], false)
	}
}

// Each kind maps onto the generic tool the rules already use; mcp and other
// keep the caller's name. acting_for and root_session_id never reach the
// evaluated payload.
func TestAgentGatewayHookPayload(t *testing.T) {
	cases := map[string]struct {
		body     string
		tool     string
		input    interface{}
		hookName string
	}{
		"shell":  {agentGatewayValidEvents["pre_tool shell"], "shell", map[string]interface{}{"command": "ls -la"}, "PreToolUse"},
		"obj":    {agentGatewayValidEvents["pre_tool obj"], "shell", map[string]interface{}{"command": "ls"}, "PreToolUse"},
		"read":   {agentGatewayValidEvents["pre_tool read"], "read_file", map[string]interface{}{"path": "/etc/hosts"}, "PreToolUse"},
		"write":  {agentGatewayValidEvents["pre_tool write"], "write_file", map[string]interface{}{"path": "/work/a.txt", "content": "x"}, "PreToolUse"},
		"fetch":  {agentGatewayValidEvents["pre_tool fetch"], "web_fetch", map[string]interface{}{"url": "https://example.com"}, "PreToolUse"},
		"mcp":    {agentGatewayValidEvents["pre_tool mcp"], "github.create_issue", map[string]interface{}{"title": "x"}, "PreToolUse"},
		"post":   {agentGatewayValidEvents["post_tool"], "shell", map[string]interface{}{"command": "ls"}, "PostToolUse"},
		"prompt": {agentGatewayValidEvents["user_prompt"], "", nil, "UserPromptSubmit"},
	}
	for name, tc := range cases {
		ev, err := DecodeAgentGatewayEvent([]byte(tc.body))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		payload, err := AgentGatewayHookPayload(ev)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if payload["hook_event_name"] != tc.hookName {
			t.Errorf("%s: event %v, want %s", name, payload["hook_event_name"], tc.hookName)
		}
		if tc.tool != "" {
			if payload["tool_name"] != tc.tool || !reflect.DeepEqual(payload["tool_input"], tc.input) {
				t.Errorf("%s: tool %v input %v, want %s %v", name, payload["tool_name"], payload["tool_input"], tc.tool, tc.input)
			}
		}
	}
	ev, err := DecodeAgentGatewayEvent([]byte(agentGatewayValidEvents["identity"]))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := AgentGatewayHookPayload(ev)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"acting_for", "root_session_id", "user", "user_id"} {
		if _, ok := payload[key]; ok {
			t.Errorf("payload carries %s: %v", key, payload)
		}
	}
	for name, body := range map[string]string{
		"shell extra key": `{"event":"pre_tool","session_id":"s","tool_use_id":"t","tool":{"name":"x","kind":"shell","input":{"command":"ls","cwd":"/"}}}`,
		"write string":    `{"event":"pre_tool","session_id":"s","tool_use_id":"t","tool":{"name":"x","kind":"file_write","input":"/a"}}`,
		"shell number":    `{"event":"pre_tool","session_id":"s","tool_use_id":"t","tool":{"name":"x","kind":"shell","input":3}}`,
	} {
		ev, err := DecodeAgentGatewayEvent([]byte(body))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := AgentGatewayHookPayload(ev); err == nil {
			t.Errorf("%s: mapped", name)
		}
	}
}

func TestAgentGatewayHookProfileDecode(t *testing.T) {
	profile := AgentGatewayHookProfile()
	if profile.Name != AgentGatewayConnectorName || !profile.Capabilities.CanBlock || len(profile.SupportedEvents) != 7 {
		t.Fatalf("profile = %+v", profile)
	}
	if !profile.ExperimentalToolLifecycleEligible() || !profile.ToolCallLifecycle.SupportsExactInvocationJoin() {
		t.Fatal("the route's tool calls do not take part in chains")
	}
	if err := ValidateToolCallLifecycleContract(profile.ToolCallLifecycle, profile.SupportedEvents); err != nil {
		t.Fatalf("lifecycle contract: %v", err)
	}
	for status, want := range map[string]ToolLifecycleOutcome{
		"success": ToolLifecycleOutcomeSuccess, "error": ToolLifecycleOutcomeFailure,
		"denied": ToolLifecycleOutcomeDenied, "cancelled": ToolLifecycleOutcomeCancelled, "": ToolLifecycleOutcomeUnknown,
	} {
		payload := map[string]interface{}{"tool_status": status}
		if status == "" {
			payload = map[string]interface{}{}
		}
		if got := profile.ToolCallLifecycle.ClassifyTerminalOutcome(AgentGatewayConnectorName, "PostToolUse", payload); got != want {
			t.Errorf("status %q: outcome %v, want %v", status, got, want)
		}
	}
	req := profile.Decode(map[string]interface{}{
		"hook_event_name": "PostToolUse", "session_id": "s", "tool_call_id": "t", "tool_name": "shell",
		"tool_input": map[string]interface{}{"command": "ls"}, "tool_response": map[string]interface{}{"out": "x"},
	})
	if req.ConnectorName != AgentGatewayConnectorName || req.SessionID != "s" || req.ToolInvocationID != "t" ||
		req.Direction != "tool_result" || req.Content == "" || string(req.ToolArgs) != `{"command":"ls"}` {
		t.Fatalf("decoded %+v", req)
	}
	prompt := profile.Decode(map[string]interface{}{"hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": "p"})
	if prompt.Direction != "prompt" || prompt.Content != "p" {
		t.Fatalf("prompt decoded %+v", prompt)
	}
}
