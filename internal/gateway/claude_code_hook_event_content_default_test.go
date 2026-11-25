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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
)

// rel-1-0-10:GAP-2161. The connector event text a Claude Code hook sends to
// Cisco AI Defense (compact summaries, loaded instructions, config changes,
// elicitations, notifications, stop errors, subagent text) was used for
// inspection only in 1.0.10. Exporting it on hook_decision is the opt-in
// guardrail.include_hook_event_content; with the default config the record
// carries no event text while the inspection still runs.

type hookEventContentCase struct {
	family string
	req    claudeCodeHookRequest
	// content is the text the hook submits to AI Defense and, with the
	// key on, carries on hook_decision.
	content string
	// aidCalls is the AI Defense calls the event makes, key on or off.
	aidCalls int32
}

func hookEventContentCases(text string) []hookEventContentCase {
	var cases []hookEventContentCase
	for _, event := range []string{
		"TaskCreated", "TaskCompleted", "TeammateIdle", "PreCompact", "Elicitation",
		"ElicitationResult", "Notification", "CwdChanged", "DirectoryAdded", "WorktreeRemove",
	} {
		cases = append(cases, hookEventContentCase{
			family: "lifecycle", req: claudeCodeHookRequest{HookEventName: event, Message: text}, content: text, aidCalls: 1,
		})
	}
	cases = append(cases, hookEventContentCase{
		family: "lifecycle",
		req: claudeCodeHookRequest{HookEventName: "PostCompact", Payload: map[string]interface{}{
			"compact_summary": text,
		}},
		content: text, aidCalls: 1,
	})
	for _, event := range []string{"InstructionsLoaded", "ConfigChange", "FileChanged"} {
		cases = append(cases, hookEventContentCase{
			family: "file event", req: claudeCodeHookRequest{HookEventName: event, Message: text}, content: text, aidCalls: 1,
		})
	}
	cases = append(cases,
		hookEventContentCase{
			family: "stop failure", req: claudeCodeHookRequest{HookEventName: "StopFailure", Error: text}, content: text, aidCalls: 1,
		},
		hookEventContentCase{
			family: "subagent start",
			req: claudeCodeHookRequest{HookEventName: "SubagentStart", Payload: map[string]interface{}{
				"task": "summarize the open pull requests", "task_description": text,
			}},
			content: text, aidCalls: 2,
		},
	)
	return cases
}

// hookEventContentAPI is a Claude Code hook evaluator whose AI Defense stub
// answers every inspection with response and counts the calls.
func hookEventContentAPI(t *testing.T, api *APIServer, cfg *config.Config, response string) *atomic.Int32 {
	t.Helper()
	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, response)
	}))
	t.Cleanup(server.Close)
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api.scannerCfg = cfg
	api.ciscoInspector = &CiscoInspectClient{apiKey: "test-key", endpoint: server.URL, client: server.Client()}
	return calls
}

func TestClaudeCodeHookEventContentIsNotRetainedByDefault(t *testing.T) {
	for _, test := range hookEventContentCases("event text that stays on the endpoint") {
		t.Run(test.family+"/"+test.req.HookEventName, func(t *testing.T) {
			api := &APIServer{}
			calls := hookEventContentAPI(t, api, &config.Config{}, `{"is_safe":true,"action":"Allow"}`)
			resp := api.evaluateClaudeCodeHook(t.Context(), test.req)
			if got := calls.Load(); got != test.aidCalls {
				t.Fatalf("AI Defense calls = %d, want %d: the content must still be inspected", got, test.aidCalls)
			}
			if resp.InspectedContentPresent || resp.InspectedContent != "" {
				t.Fatalf("default config retained event content for hook_decision: (%q, %t)",
					resp.InspectedContent, resp.InspectedContentPresent)
			}
		})
	}
}

func TestClaudeCodeHookDecisionCarriesNoEventContentByDefault(t *testing.T) {
	seen := map[string]bool{}
	for _, test := range hookEventContentCases("event text that stays on the endpoint") {
		if seen[test.family] {
			continue
		}
		seen[test.family] = true
		t.Run(test.family+"/"+test.req.HookEventName, func(t *testing.T) {
			api, capture := bindHookModelV8Runtime(t, []string{"logs"})
			calls := hookEventContentAPI(t, api, &config.Config{}, `{"is_safe":true,"action":"Allow"}`)
			resp := claudeCodeResponseToAgentHookResponse(api.evaluateClaudeCodeHook(t.Context(), test.req))
			if got := calls.Load(); got != test.aidCalls {
				t.Fatalf("AI Defense calls = %d, want %d", got, test.aidCalls)
			}
			api.emitHookDecisionObservabilityV8(t.Context(),
				agentHookRequest{ConnectorName: "claudecode", HookEventName: test.req.HookEventName},
				resp, HookAuditEnvelope{Result: "ok"}, false)
			body := capturedHookDecisionBody(t, capture)
			if messages, ok := body["gen_ai.input.messages"]; ok {
				t.Fatalf("default hook_decision carries event content: gen_ai.input.messages=%v", messages)
			}
		})
	}
}

// capturedHookDecisionBody waits for the one generated hook_decision log and
// returns its body.
func capturedHookDecisionBody(t *testing.T, capture *hookModelV8OTLPCapture) map[string]interface{} {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var records []*logspb.LogRecord
	for time.Now().Before(deadline) {
		records = hookModelV8CapturedLogs(capture.logSnapshot())
		if len(records) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(records) != 1 {
		t.Fatalf("generated hook decision logs=%d want=1", len(records))
	}
	var wire struct {
		Body map[string]interface{} `json:"body"`
	}
	if err := json.Unmarshal([]byte(records[0].Body.GetStringValue()), &wire); err != nil {
		t.Fatalf("decode generated hook decision body: %v", err)
	}
	if wire.Body == nil {
		t.Fatal("generated hook decision has no body")
	}
	return wire.Body
}
