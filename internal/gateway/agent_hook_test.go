// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestMapHookAction_ConfirmRequiresNativeAskSurface(t *testing.T) {
	copilot := connector.NewCopilotConnector().HookCapabilities(connector.SetupOpts{})
	action, wouldBlock := mapHookAction("confirm", "action", "PreToolUse", copilot)
	if action != "confirm" || wouldBlock {
		t.Fatalf("copilot PreToolUse confirm = (%q,%v), want (confirm,false)", action, wouldBlock)
	}

	windsurf := connector.NewWindsurfConnector().HookCapabilities(connector.SetupOpts{})
	action, wouldBlock = mapHookAction("confirm", "action", "pre_run_command", windsurf)
	if action != "alert" || wouldBlock {
		t.Fatalf("windsurf confirm = (%q,%v), want explicit alert downgrade", action, wouldBlock)
	}

	cursor := connector.NewCursorConnector().HookCapabilities(connector.SetupOpts{})
	action, wouldBlock = mapHookAction("confirm", "action", "preToolUse", cursor)
	if action != "alert" || wouldBlock {
		t.Fatalf("cursor preToolUse confirm = (%q,%v), want alert because ask is not documented for that surface", action, wouldBlock)
	}
}

func TestMapHookAction_ObserveAndUnsupportedBlock(t *testing.T) {
	hermes := connector.NewHermesConnector().HookCapabilities(connector.SetupOpts{})
	action, wouldBlock := mapHookAction("block", "observe", "pre_tool_call", hermes)
	if action != "allow" || !wouldBlock {
		t.Fatalf("observe block = (%q,%v), want allow/would_block", action, wouldBlock)
	}

	action, wouldBlock = mapHookAction("block", "action", "post_tool_call", hermes)
	if action != "allow" || !wouldBlock {
		t.Fatalf("unsupported block event = (%q,%v), want allow/would_block", action, wouldBlock)
	}
}

func TestNormalizeAgentHookMode_EnforceAlias(t *testing.T) {
	if got := normalizeAgentHookMode("enforce"); got != "action" {
		t.Fatalf("normalizeAgentHookMode(enforce) = %q, want action", got)
	}
	if got := normalizeAgentHookMode("warn"); got != "observe" {
		t.Fatalf("normalizeAgentHookMode(warn) = %q, want observe", got)
	}
}

func TestHandleAgentHook_EnrichesHTTPSpanWithAgentIdentity(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	defer otel.SetTracerProvider(prev)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	api := &APIServer{}
	handler := otelHTTPServerMiddleware("sidecar-api", http.HandlerFunc(api.handleAgentHook("copilot")))
	body, err := json.Marshal(map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"session_id":      "session-generic",
		"turn_id":         "turn-generic",
		"agent_id":        "github-copilot-cli",
		"agent_name":      "GitHub Copilot CLI",
		"agent_type":      "copilot-cli",
		"tool_name":       "shell",
		"tool_input": map[string]interface{}{
			"command": "echo ok",
		},
	})
	if err != nil {
		t.Fatalf("marshal hook body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", w.Code, w.Body.String())
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans want 1", len(spans))
	}
	for key, want := range map[string]string{
		"gen_ai.conversation.id": "session-generic",
		"gen_ai.operation.id":    "turn-generic",
		"gen_ai.agent.name":      "GitHub Copilot CLI",
		"gen_ai.agent.type":      "copilot-cli",
		"gen_ai.agent.id":        "github-copilot-cli",
		"defenseclaw.connector":  "copilot",
		"defenseclaw.hook.event": "PreToolUse",
	} {
		got, ok := attrByKey(spans[0].Attributes, key)
		if !ok || got.AsString() != want {
			t.Fatalf("%s=%q ok=%v want %q", key, got.AsString(), ok, want)
		}
	}
}
