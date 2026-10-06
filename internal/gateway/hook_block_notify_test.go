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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1145: an enforced connector-hook block reaches the configured
// webhooks; an observe-mode would-block does not.
func TestHookBlockDispatchesWebhook(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	var mu sync.Mutex
	var payloads []map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&m); err == nil {
			mu.Lock()
			payloads = append(payloads, m)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := NewWebhookDispatcher([]config.WebhookConfig{{
		URL: srv.URL, Type: "generic", MinSeverity: "HIGH", Enabled: true,
		Events: []string{"block"},
	}})
	api := &APIServer{} // no OS notifier: webhooks must not depend on it
	api.SetWebhookSource(func() *WebhookDispatcher { return d })

	req := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Bash"}
	api.dispatchClaudeCodeHookNotification(context.Background(), req, "allow", "block", "CRITICAL", "matched: X", true, hookEvaluationContext{})
	// GAP-0144: the alert names the account, the agent identity and the host.
	identified := ContextWithAgentIdentity(context.Background(), AgentIdentity{
		UserID: "1001", UserName: "alice", IdentityID: "agt-0123456789abcdef",
	})
	api.dispatchClaudeCodeHookNotification(identified, req, "block", "block", "CRITICAL", "matched: X", false, hookEvaluationContext{})
	d.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(payloads) != 1 {
		t.Fatalf("want 1 webhook delivery for the enforced block, got %d", len(payloads))
	}
	event, _ := payloads[0]["event"].(map[string]interface{})
	for key, want := range map[string]string{"user_id": "1001", "user_name": "alice", "agent_identity_id": "agt-0123456789abcdef", "host": webhookHostname()} {
		if got, _ := event[key].(string); got != want || want == "" {
			t.Errorf("webhook event %s = %q, want %q", key, got, want)
		}
	}
	body, _ := json.Marshal(payloads[0])
	for _, want := range []string{"Bash", "claudecode", "CRITICAL"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("webhook payload missing %q: %s", want, body)
		}
	}
}

// GAP-1351: the webhook names the rule that blocked while the reason text
// stays redacted.
func TestHookBlockWebhookNamesRule(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	got := make(chan map[string]interface{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&m); err == nil {
			got <- m
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := NewWebhookDispatcher([]config.WebhookConfig{{
		URL: srv.URL, Type: "generic", MinSeverity: "HIGH", Enabled: true, Events: []string{"block"},
	}})
	api := &APIServer{}
	api.SetWebhookSource(func() *WebhookDispatcher { return d })
	req := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Bash"}
	api.dispatchClaudeCodeHookNotification(context.Background(), req, "block", "block", "CRITICAL",
		"matched: VB2-MARKER-BLOCK:Verify batch 2 marker command (block)", false,
		hookEvaluationContext{RuleIDs: []string{"VB2-MARKER-BLOCK", "not a rule id"}})
	d.Close()

	payload := <-got
	event, _ := payload["event"].(map[string]interface{})
	details, _ := event["details"].(string)
	if !strings.Contains(details, "rule=VB2-MARKER-BLOCK reason=<redacted") {
		t.Errorf("details should name the rule and keep the reason redacted: %q", details)
	}
	if strings.Contains(details, "Verify batch") || strings.Contains(details, "not a rule id") {
		t.Errorf("details leaked reason text: %q", details)
	}
	if rule, _ := event["defenseclaw_rule"].(string); rule != "rule VB2-MARKER-BLOCK" {
		t.Errorf("defenseclaw_rule = %q, want %q", rule, "rule VB2-MARKER-BLOCK")
	}
}
