// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// Cursor's terminal event kind is authoritative even when a successful
// result carries a reason referring to an earlier failed probe.
func TestCursorWriteAfterMissingReadIsCompleted(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs"})
	store, logger := testStoreAndLogger(t)
	api.store, api.logger = store, logger
	api.health = NewSidecarHealth()
	api.scannerCfg = &config.Config{}
	handler := api.handleAgentHook("cursor")

	for _, body := range []string{
		`{"hook_event_name":"preToolUse","conversation_id":"cursor-write","generation_id":"turn-1","tool_name":"Read","tool_use_id":"call-1","tool_input":{"file_path":"x.txt"}}`,
		`{"hook_event_name":"postToolUseFailure","conversation_id":"cursor-write","generation_id":"turn-1","tool_name":"Read","tool_use_id":"call-1","error_message":"File not found: x.txt"}`,
		`{"hook_event_name":"preToolUse","conversation_id":"cursor-write","generation_id":"turn-1","tool_name":"Write","tool_use_id":"call-1","tool_input":{"file_path":"x.txt","content":"one"}}`,
		`{"hook_event_name":"postToolUse","conversation_id":"cursor-write","generation_id":"turn-1","tool_name":"Write","tool_use_id":"call-1","reason":"File not found: x.txt","tool_output":{"file_path":"x.txt","success":true}}`,
	} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/api/v1/cursor/hook", strings.NewReader(body))
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("hook status=%d body=%s", response.Code, response.Body.String())
		}
	}

	var results = map[string]map[string]any{}
	eventuallyTrue(t, func() bool {
		for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
			name := logStringAttribute(record.GetAttributes(), "defenseclaw.event.name")
			if name != observability.TelemetryEventToolInvocationCompleted &&
				name != observability.TelemetryEventToolInvocationFailed {
				continue
			}
			var wire struct {
				Body map[string]any `json:"body"`
			}
			if err := json.Unmarshal([]byte(record.GetBody().GetStringValue()), &wire); err != nil {
				t.Fatalf("decode tool log: %v", err)
			}
			if tool, ok := wire.Body["gen_ai.tool.name"].(string); ok {
				wire.Body["event_name"] = name
				wire.Body["severity"] = record.GetSeverityText()
				results[tool] = wire.Body
			}
		}
		return results["Read"] != nil && results["Write"] != nil
	})
	if got := results["Read"]; got["event_name"] != observability.TelemetryEventToolInvocationFailed ||
		got["defenseclaw.tool.status"] != "failed" {
		t.Fatalf("missing-file Read audit = %v", got)
	}
	if got := results["Write"]; got["event_name"] != observability.TelemetryEventToolInvocationCompleted ||
		got["defenseclaw.tool.status"] != "completed" || got["severity"] != "INFO" {
		t.Fatalf("successful Write audit = %v", got)
	}
}

func TestHookToolLogsV8RouteRequestedAndCompletedContent(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs"})
	meta := richHookModelV8Meta()
	meta.Phase = "tool"
	meta.ToolID = "tool-call-1"
	meta.ToolName = "shell"
	const arguments = `{"command":"echo tool.person@example.com"}`
	const result = `{"output":"tool.person@example.com"}`
	api.emitToolInvocationEventV8(t.Context(), meta, "call", "shell", arguments, "", nil)
	api.emitToolInvocationEventV8(t.Context(), meta, "result", "shell", "", result, nil)

	deadline := time.Now().Add(3 * time.Second)
	var wire []byte
	var names map[string]bool
	for time.Now().Before(deadline) {
		wire, names = capturedModelLogWire(t, capture)
		if names[observability.TelemetryEventToolInvocationRequested] &&
			names[observability.TelemetryEventToolInvocationCompleted] {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !names[observability.TelemetryEventToolInvocationRequested] ||
		!names[observability.TelemetryEventToolInvocationCompleted] {
		t.Fatalf("canonical tool log events=%v", names)
	}
	if !bytes.Contains(wire, []byte("tool.person@example.com")) {
		t.Fatal("default redaction_profile none did not preserve tool source content")
	}
}

// GAP-0202: a sandboxed session's tool records carry the sandbox binding, so
// they join its hook decisions, model and lifecycle records.
func TestHookToolLogsV8CarrySandboxIdentity(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs"})
	const sandboxID, sandboxName = "0f5b3c2e-9d4a-4f61-8a7e-2c1b0d9e6f33", "dc-codex-app-0a1b"
	ctx := audit.ContextWithEnvelope(t.Context(), audit.CorrelationEnvelope{SandboxID: sandboxID, SandboxName: sandboxName})
	meta := richHookModelV8Meta()
	meta.Phase = "tool"
	meta.ToolID = "tool-call-sandbox"
	api.emitToolInvocationEventV8(ctx, meta, "call", "shell", `{"command":"ls"}`, "", nil)
	api.emitToolInvocationEventV8(ctx, meta, "result", "shell", "", `{"output":"ok"}`, nil)
	eventuallyTrue(t, func() bool { return len(hookModelV8CapturedLogs(capture.logSnapshot())) >= 2 })
	for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
		var wire struct {
			Body map[string]any `json:"body"`
		}
		name := logStringAttribute(record.GetAttributes(), "defenseclaw.event.name")
		if err := json.Unmarshal([]byte(record.GetBody().GetStringValue()), &wire); err != nil {
			t.Fatalf("%s body: %v", name, err)
		}
		if wire.Body["defenseclaw.sandbox.id"] != sandboxID || wire.Body["defenseclaw.sandbox.name"] != sandboxName {
			t.Errorf("%s body = %v, want the sandbox id and name", name, wire.Body)
		}
	}
}
