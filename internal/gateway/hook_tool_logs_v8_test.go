// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"testing"
	"time"

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
