// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestAntigravityProfileDecodeOfficialEvents(t *testing.T) {
	common := map[string]interface{}{
		"conversationId":        "conversation-1",
		"workspacePaths":        []interface{}{`C:\work\repo`},
		"transcriptPath":        `C:\Users\Kevin\.gemini\antigravity-cli\transcript.jsonl`,
		"artifactDirectoryPath": `C:\Users\Kevin\.gemini\antigravity-cli\artifacts`,
	}
	cases := []struct {
		name      string
		event     string
		extra     map[string]interface{}
		direction string
		tool      string
		content   string
	}{
		{
			name: "PreToolUse", event: "PreToolUse",
			extra: map[string]interface{}{
				"stepIdx": float64(7),
				"toolCall": map[string]interface{}{
					"name": "run_command",
					"args": map[string]interface{}{"Cwd": `C:\work\repo`, "CommandLine": "Write-Output integration-test"},
				},
			},
			direction: "tool_call", tool: "run_command", content: "Write-Output integration-test",
		},
		{name: "PostToolUse", event: "PostToolUse", extra: map[string]interface{}{"stepIdx": float64(7), "error": "access denied"}, direction: "tool_result", tool: "tool", content: "access denied"},
		{name: "PreInvocation", event: "PreInvocation", extra: map[string]interface{}{"invocationNum": float64(2), "initialNumSteps": float64(1)}, tool: "invocation"},
		{name: "PostInvocation", event: "PostInvocation", extra: map[string]interface{}{"invocationNum": float64(2), "initialNumSteps": float64(1)}, tool: "invocation"},
		{name: "Stop", event: "Stop", extra: map[string]interface{}{"executionNum": float64(3), "terminationReason": "complete", "fullyIdle": true}, tool: "session", content: "complete"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]interface{}{}
			for key, value := range common {
				payload[key] = value
			}
			for key, value := range tc.extra {
				payload[key] = value
			}
			payload["hookEventName"] = tc.event
			got := antigravityProfileDecode(payload)
			if got.HookEventName != tc.event || got.SessionID != "conversation-1" {
				t.Fatalf("identity = %+v", got)
			}
			if got.Direction != tc.direction || got.ToolName != tc.tool || got.Content != tc.content {
				t.Fatalf("decoded = %+v", got)
			}
			if tc.event == "PreToolUse" {
				var args map[string]interface{}
				if err := json.Unmarshal(got.ToolArgs, &args); err != nil {
					t.Fatalf("ToolArgs are not valid JSON: %v", err)
				}
				want := tc.extra["toolCall"].(map[string]interface{})["args"]
				if !reflect.DeepEqual(args, want) {
					t.Fatalf("ToolArgs=%v, want %v", args, want)
				}
				if !got.ToolArgsAuthoritative {
					t.Fatal("PreToolUse args projection is not authoritative")
				}
			} else if len(got.ToolArgs) != 0 {
				t.Fatalf("%s unexpectedly supplied ToolArgs: %s", tc.event, got.ToolArgs)
			}
			if got.CWD != `C:\work\repo` || got.TurnID != "" {
				t.Fatalf("workspace/correlation = %+v", got)
			}
		})
	}
}

func TestAntigravityProfileDecodeDoesNotReuseClaudeFields(t *testing.T) {
	got := antigravityProfileDecode(map[string]interface{}{
		"hookEventName": "PostInvocation",
		"prompt":        "untrusted compatibility prompt",
		"modelResponse": "untrusted compatibility response",
		"toolResponse":  map[string]interface{}{"output": "untrusted compatibility output"},
	})
	if got.Content != "" || got.Direction != "" {
		t.Fatalf("undocumented fields affected decode: %+v", got)
	}
}

func TestAntigravityLegacyEventlessPreToolUseMigration(t *testing.T) {
	got := antigravityProfileDecode(map[string]interface{}{
		"toolCall": map[string]interface{}{"name": "run_command", "args": map[string]interface{}{}},
	})
	if got.HookEventName != "PreToolUse" {
		t.Fatalf("legacy event=%q", got.HookEventName)
	}
}

func TestAntigravityToolArgsFromRawPayloadStrictEnvelope(t *testing.T) {
	raw := []byte(`{"hookEventName":"PreToolUse","toolCall":{"name":"run_command","args": { "CommandLine": "Write-Output integration-test", "Cwd": "C:\\work" }}}`)
	want := json.RawMessage(`{ "CommandLine": "Write-Output integration-test", "Cwd": "C:\\work" }`)
	if got := antigravityToolArgsFromRawPayload(raw); string(got) != string(want) {
		t.Fatalf("ToolArgs=%q want exact raw nested object %q", got, want)
	}
	for _, raw := range []string{
		`{"toolCall":{"name":"run_command","args":{"CommandLine":"Write-Output first"},"args":{"CommandLine":"Write-Output second"}}}`,
		`{"toolCall":{"name":"run_command","args":{"CommandLine":"Write-Output first"},"arguments":{"CommandLine":"Write-Output second"}}}`,
		`{"toolCall":{"name":"run_command","args":"opaque"}}`,
		`{"toolCall":{"name":"   ","args":{}}}`,
		`{"toolCall":{"name":"run_command","args":{`,
	} {
		if got := antigravityToolArgsFromRawPayload([]byte(raw)); got != nil {
			t.Fatalf("ToolArgs=%s want nil for ambiguous or malformed envelope", got)
		}
	}

	nested := strings.Repeat("[", antigravityMaxJSONNestingDepth) + "0" + strings.Repeat("]", antigravityMaxJSONNestingDepth)
	deep := []byte(`{"toolCall":{"name":"run_command","args":{"nested":` + nested + `}}}`)
	if !json.Valid(deep) || antigravityToolArgsFromRawPayload(deep) != nil {
		t.Fatal("excessively nested payload was not rejected")
	}
}
