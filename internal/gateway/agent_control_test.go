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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestAgentControlEvaluateDeny(t *testing.T) {
	t.Setenv("AGENT_CONTROL_API_KEY", "test-key")

	var got agentControlEvaluationRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != agentControlEvaluationPath {
			t.Fatalf("path = %q, want %q", r.URL.Path, agentControlEvaluationPath)
		}
		if r.Header.Get("X-API-Key") != "test-key" {
			t.Fatalf("X-API-Key = %q, want test-key", r.Header.Get("X-API-Key"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"is_safe": false,
			"confidence": 0.98,
			"reason": "matched deny control",
			"matches": [{
				"control_id": 2,
				"control_name": "deny-dangerous-shell-pre-tool",
				"action": "deny",
				"result": {"matched": true, "confidence": 0.99, "message": "dangerous command"}
			}],
			"errors": [],
			"non_matches": []
		}`))
	}))
	defer server.Close()

	client := newAgentControlClient(config.AgentControlConfig{
		Enabled:   true,
		URL:       server.URL,
		TimeoutMS: 1000,
		AgentName: "defenseclaw-openclaw",
		FailMode:  "open",
	}, "openclaw")
	if client == nil {
		t.Fatal("client is nil")
	}

	decision := client.evaluate(t.Context(), "pre", agentControlStep{
		Type:  "tool",
		Name:  "shell",
		Input: map[string]interface{}{"command": "kubectl delete pod x"},
	})
	if decision == nil {
		t.Fatal("decision is nil")
	}
	if !decision.Matched || decision.Action != "deny" || decision.ControlID != 2 {
		t.Fatalf("decision = %+v, want matched deny control 2", decision)
	}
	if got.AgentName != "defenseclaw-openclaw" || got.Stage != "pre" || got.Step.Type != "tool" || got.Step.Name != "shell" {
		t.Fatalf("request = %+v", got)
	}
}

func TestAgentControlFailClosedDenies(t *testing.T) {
	client := newAgentControlClient(config.AgentControlConfig{
		Enabled:   true,
		URL:       "http://127.0.0.1:1",
		TimeoutMS: 1,
		AgentName: "defenseclaw-openclaw",
		FailMode:  "closed",
	}, "openclaw")

	decision := client.errorDecision("pre", agentControlStep{Type: "tool", Name: "shell", Input: "x"}, 0, http.ErrServerClosed)
	if decision.Action != "deny" || !decision.Matched || decision.IsSafe {
		t.Fatalf("decision = %+v, want fail-closed deny", decision)
	}
}

func TestMergeAgentControlIntoToolVerdict(t *testing.T) {
	verdict := &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	decision := &agentControlDecision{
		Enabled:     true,
		Matched:     true,
		IsSafe:      false,
		Action:      "deny",
		ControlID:   2,
		ControlName: "deny-dangerous-shell-pre-tool",
		Confidence:  0.99,
		Reason:      "dangerous command",
	}

	mergeAgentControlIntoToolVerdict(verdict, decision)

	if verdict.Action != "block" || verdict.Severity != "HIGH" {
		t.Fatalf("verdict = %+v, want block/HIGH", verdict)
	}
	if verdict.AgentControl == nil || verdict.AgentControl.ControlID != 2 {
		t.Fatalf("agent control decision missing from verdict: %+v", verdict)
	}
}
