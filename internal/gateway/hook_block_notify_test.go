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
	api.dispatchClaudeCodeHookNotification(req, "allow", "block", "CRITICAL", "matched: X", true, hookEvaluationContext{})
	api.dispatchClaudeCodeHookNotification(req, "block", "block", "CRITICAL", "matched: X", false, hookEvaluationContext{})
	d.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(payloads) != 1 {
		t.Fatalf("want 1 webhook delivery for the enforced block, got %d", len(payloads))
	}
	body, _ := json.Marshal(payloads[0])
	for _, want := range []string{"Bash", "claudecode", "CRITICAL"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("webhook payload missing %q: %s", want, body)
		}
	}
}
