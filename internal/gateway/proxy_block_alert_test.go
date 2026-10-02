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
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// GAP-1895: the alert row of a proxy prompt block says what was blocked and
// why instead of only "enforcement.block.applied".
func TestProxyPromptBlockAlertNamesDirectionAndReason(t *testing.T) {
	insp := newMockInspector()
	insp.setVerdict("prompt", &ScanVerdict{Action: "block", Severity: "CRITICAL",
		Reason: "matched: R-PROMPT:Test marker prompt", Findings: []string{"R-PROMPT:Test marker prompt"}})
	proxy := newTestProxy(t, &mockProvider{}, insp, "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.bindObservabilityV8Trace(runtime)

	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"dccert-prompt-marker"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	proxy.handleChatCompletion(httptest.NewRecorder(), req)

	database, err := sql.Open("sqlite", capture.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var target, details string
	if err := database.QueryRow(`
		SELECT COALESCE(target, ''), COALESCE(details, '') FROM audit_events
		WHERE event_name = ?`, observability.TelemetryEventEnforcementBlockApplied,
	).Scan(&target, &details); err != nil {
		t.Fatal(err)
	}
	want := "decision=blocked direction=prompt reason=matched: R-PROMPT:Test marker prompt"
	if target != "prompt" || details != want {
		t.Fatalf("block alert target=%q details=%q, want prompt / %q", target, details, want)
	}
}
