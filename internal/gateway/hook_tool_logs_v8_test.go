// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

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
